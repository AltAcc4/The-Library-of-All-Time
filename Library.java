import java.math.BigInteger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import java.awt.*;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import javax.swing.*;


class LibCipher {

    private final byte[] masterKey;
    private final int rounds;
    
    private final BigInteger maxBookCapacity;
    private final BigInteger leftHalfDomain;
    private final BigInteger rightHalfDomain;
    private final int byteLengthPerHalf;
    
    private static final int BOOK_SIZE = 410 * 40 * 80; // 1312000
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./[\\]^_`:;<=>?@{|}~ ";
    private static final Map<Integer, BigInteger> powerCache = new ConcurrentHashMap<>();

    private final ThreadLocal<MessageDigest> shaHolder = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 initialization failed in Cipher.shaHolder");
        }
    });

    // ThreadLocal to reuse the AES Engine per thread for maximum speed
    private final ThreadLocal<Cipher> aesHolder = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/CTR/NoPadding");
        } catch (Exception e) {
            throw new RuntimeException("AES/CTR framework initialization failed in Cipher.aesHolder", e);
        }
    });

    public LibCipher(BigInteger maxBookCapacity) {
        String key = "Does the Black Moon howl?";
        
        // hash arbitrary string to derive cryptographically sound 256-bit AES master key
        try {
            MessageDigest sha = shaHolder.get();
            sha.reset();
            this.masterKey = sha.digest(key.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Key hash via SHA-256 failed in LibCipher(BigInteger)", e);
        }
        
        this.rounds = 4;
        this.maxBookCapacity = maxBookCapacity;

        int rightLength = BOOK_SIZE / 2;
        int leftLength = BOOK_SIZE - rightLength;

        this.rightHalfDomain = BigInteger.valueOf(95).pow(rightLength);
        this.leftHalfDomain = BigInteger.valueOf(95).pow(leftLength);
        
        // precompute physical byte depth required to safely mask half block
        this.byteLengthPerHalf = (leftHalfDomain.bitLength() + 7) / 8;
    }

    public BigInteger encrypt(BigInteger bookID) {
        if (bookID.signum() < 0 || bookID.compareTo(maxBookCapacity) >= 0) {
            throw new IllegalArgumentException("Invalid bookID in LibCipher.encrypt(>BigInteger)");
        }

        BigInteger[] split = bookID.divideAndRemainder(rightHalfDomain);
        BigInteger left = split[0];
        BigInteger right = split[1];

        for (int i = 0; i < rounds; i++) {
            BigInteger nextLeft = right;
            BigInteger roundHash = roundFunction(right, i, leftHalfDomain);
            
            BigInteger nextRight = left.add(roundHash).mod(leftHalfDomain);

            left = nextLeft;
            right = nextRight;
        }

        return left.multiply(rightHalfDomain).add(right);
    }

    public BigInteger decrypt(BigInteger scrambledID) {
        if (scrambledID.signum() < 0 || scrambledID.compareTo(maxBookCapacity) >= 0) {
            throw new IllegalArgumentException("Invalid scrambledID in LibCipher.decrypt(>BigInteger)");
        }

        BigInteger[] split = scrambledID.divideAndRemainder(rightHalfDomain);
        BigInteger left = split[0];
        BigInteger right = split[1];

        for (int i = rounds - 1; i >= 0; i--) {
            BigInteger nextRight = left;
            BigInteger roundHash = roundFunction(left, i, leftHalfDomain);
            
            BigInteger nextLeft = right.subtract(roundHash).mod(leftHalfDomain);
            if (nextLeft.signum() < 0) {
                nextLeft = nextLeft.add(leftHalfDomain);
            }

            left = nextLeft;
            right = nextRight;
        }

        return left.multiply(rightHalfDomain).add(right);
    }

    // high-entropy PRF built on AES-CTR stream expansion generates a fully dynamic mask scaled exactly to number of bits in the half-block domain
    private BigInteger roundFunction(BigInteger half, int round, BigInteger modulusBound) {
        try {
            javax.crypto.Cipher aesCtr = aesHolder.get();
            
            // uniquely seed round key by mixing the master key with internal half-block state
            MessageDigest sha = shaHolder.get();
            sha.reset();
            sha.update(masterKey);
            sha.update(half.toByteArray());
            byte[] roundKeyBytes = sha.digest();
            SecretKeySpec roundKey = new SecretKeySpec(roundKeyBytes, "AES");

            // use round index directly as unique IV/Counter value
            byte[] iv = new byte[16];
            ByteBuffer.wrap(iv).putInt(0, round);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // initialize stream LibCipher
            aesCtr.init(javax.crypto.Cipher.ENCRYPT_MODE, roundKey, ivSpec);

            // stream-extract pure high-entropy pseudorandom bytes to fit block size
            byte[] blankStreamInput = new byte[byteLengthPerHalf];
            byte[] extendedRandomBytes = aesCtr.doFinal(blankStreamInput);

            // build BigInteger block and safely bind to modulus limits
            BigInteger hashBigInt = new BigInteger(1, extendedRandomBytes);
            return hashBigInt.mod(modulusBound);

        } catch (Exception e) {
            throw new RuntimeException("Stream LibCipher generation failure in LibCipher.roundFunction(BigInteger, int, BigInteger)", e);
        }
    }

    public static String toText(BigInteger scrambledID) {
        char[] text = new char[BOOK_SIZE];
        char[] alphabetArr = ALPHABET.toCharArray();
        
        if (scrambledID == null || scrambledID.signum() <= 0) {
            throw new IllegalArgumentException("Invalid scrambledID in LibCipher.toText(>BigInteger)");
        }

        toBase95(scrambledID, text, 0, BOOK_SIZE, alphabetArr);
        return new String(text);
    }

    private static void toBase95(BigInteger value, char[] target, int offset, int length, char[] alphabet) {
        // compute last 5 if small enough
         if (length <= 5) {
            long val = value.longValue();
            for (int i = length - 1; i >= 0; i--) {
                target[offset + i] = alphabet[(int) (val % 95)];
                val /= 95;
            }
            return;
        }
    
        int halfLength = length / 2;
        int leftLength = length - halfLength;
    
        // fetch power of 95
        BigInteger splitBase = powerCache.computeIfAbsent(halfLength, k -> BigInteger.valueOf(95).pow(k));

        // check for A's
        if (value.compareTo(splitBase) < 0) {
            java.util.Arrays.fill(target, offset, offset + leftLength, alphabet[0]);
            toBase95(value, target, offset + leftLength, halfLength, alphabet);
        } else {
            BigInteger[] parts = value.divideAndRemainder(splitBase);
            // note: wrap in forkjoin if needed
            toBase95(parts[0], target, offset, leftLength, alphabet);
            toBase95(parts[1], target, offset + leftLength, halfLength, alphabet);
        }
    }

    public static BigInteger toBase95(String text) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("Invalid text in LibCipher.toScrambledID(>String)");
        }

        // split if length is over 1250
        if (text.length() > 1250) {
            int mid = text.length() / 2;
            String firstHalf = text.substring(0, mid);
            String secondHalf = text.substring(mid);

            BigInteger firstValue = toBase95(firstHalf);
            BigInteger secondValue = toBase95(secondHalf);

            // Shift the first half up by 95^(length of second half) and add the second half
            BigInteger base = BigInteger.valueOf(95);
            return firstValue.multiply(base.pow(secondHalf.length())).add(secondValue);
        }

        int chunk = 1;
        for (int i = 2; i < 10; i++) {
            if (text.length() % i == 0) {
                chunk = i;
            }
        }

        BigInteger result = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(95);

        BigInteger[] numbers = new BigInteger[95];
        for (int i = 0; i < 95; i++) {
            numbers[i] = BigInteger.valueOf(i);
        }

        for (int i = 0; i < text.length(); i += chunk) {
            char[] chars = text.substring(i, i + chunk).toCharArray();
            BigInteger add = BigInteger.ZERO;

            // get value of chunk
            for (int j = 0; j < chunk; j++) {
                int index = ALPHABET.indexOf(chars[j]);
                if (index == -1) {
                    throw new IllegalArgumentException("Character '" + chars[j] + "' not found in LibCipher.ALPHABET in LibCipher.toBase95(String)");
                }
                add = add.multiply(base).add(numbers[index]);
            }

            // shift value up by chunk base positions and add value of chunk
            result = result.multiply(base.pow(chunk)).add(add);
        }

        return result;
    }
}




class Core {

    private static final BigInteger BOOKS_PER_SECTION = BigInteger.valueOf(100);
    private static final BigInteger SECTIONS_PER_SHELF = BigInteger.valueOf(128);
    private static final BigInteger BOOKS_PER_SHELF = BOOKS_PER_SECTION.multiply(SECTIONS_PER_SHELF); // 12800

    // calculates unique BigInteger BookID from physical coordinates
    public static BigInteger bookID(BigInteger shelfID, int sectionID, int bookIndexSection) {

        // prevent invalid coordinates
        if (shelfID == null || shelfID.signum() < 0) {
            throw new IllegalArgumentException("Invalid shelfID in Core.bookID(>BigInteger, int, int)");
        }
        if (sectionID < 0 || sectionID >= SECTIONS_PER_SHELF.intValue()) {
            throw new IllegalArgumentException("Invalid sectionID in Core.bookID(BigInteger, >int, int)");
        }
        if (bookIndexSection < 0 || bookIndexSection >= BOOKS_PER_SECTION.intValue()) {
            throw new IllegalArgumentException("Invalid index in Core.bookID(BigInteger, int, >int)");
        }

        BigInteger shelfOffset = shelfID.multiply(BOOKS_PER_SHELF);
        BigInteger sectionOffset = BigInteger.valueOf(sectionID).multiply(BOOKS_PER_SECTION);
        BigInteger bookOffset = BigInteger.valueOf(bookIndexSection);

        // final number is 12800 (books per shelf) times the shelfID 
        // plus 100 (books per section) times the sectionID (0 - 127)
        // plus the bookIndexSection (0 - 99)

        return shelfOffset.add(sectionOffset).add(bookOffset);
    }

    public static BigInteger[] bookLoc(BigInteger bookID) {
        if (bookID == null || bookID.signum() < 0) {
            throw new IllegalArgumentException("Invalid bookID");
        }

        BigInteger[] rtrn = new BigInteger[3];

        // separate shelf
        BigInteger[] shelfSplit = bookID.divideAndRemainder(BOOKS_PER_SHELF);
        rtrn[0] = shelfSplit[0]; // shelfID

        // separate section and index from remainder
        BigInteger[] sectionSplit = shelfSplit[1].divideAndRemainder(BOOKS_PER_SECTION);
        rtrn[1] = sectionSplit[0]; // sectionID
        rtrn[2] = sectionSplit[1]; // bookIndexSection

        // validation checks
        if (rtrn[0] == null || rtrn[0].signum() < 0) {
            throw new IllegalArgumentException("Invalid bookID.shelf in Core.bookLoc(>BigInteger)");
        }
        if (rtrn[1].intValue() < 0 || rtrn[1].intValue() >= SECTIONS_PER_SHELF.intValue()) {
            throw new IllegalArgumentException("Invalid bookID.section in Core.bookLoc(>BigInteger)");
        }
        if (rtrn[2].intValue() < 0 || rtrn[2].intValue() >= BOOKS_PER_SECTION.intValue()) {
            throw new IllegalArgumentException("Invalid bookID.index in Core.bookLoc(>BigInteger)");
        }

        return rtrn;
    }
}

class Amount {
    public static final BigInteger BOOK_AMOUNT;
    static {
        BigInteger base = new BigInteger("95");
        BOOK_AMOUNT = base.pow(1312000);
    }
}

class Book {
    // 410 pages of 40 lines each of 80 characters each
    // uses key to determine contents

    public BigInteger bookID;
    private String text;
    private int page;

    public Book(BigInteger bookID, LibCipher LibCipher) {
        text = LibCipher.toText(LibCipher.encrypt(bookID));
        page = 1;
    }
    
    public Book(BigInteger bookID, LibCipher LibCipher, String command) {
        this.bookID = bookID;
        if (command.equalsIgnoreCase("standard")) {
            text = LibCipher.toText(LibCipher.encrypt(bookID));
        } else if (command.equalsIgnoreCase("encrypted")) {
            text = LibCipher.toText(bookID);
        }
        page = 1;
    }

    public String read() {
        String rtrn = "";
        
        // get text of page (each page has 3200 characters)
        for (int i = 0; i < 40; i++) {
            int pageStart = (page - 1) * 3200;
            int lineStart = i * 80;
            rtrn += text.substring(pageStart + lineStart, pageStart + lineStart + 80) + (i != 39 ? "\n" : "");
        }
        
        return rtrn;
    }

    public void flipForward() {
        page += (page == 410) ? 0 : 1;
    }

    public void flipBackward() {
        page -= (page == 1) ? 0 : 1;
    }

    public void setPage(int page) {
        if (page > 410) {
            this.page = 410;
        } else if (page < 1) {
            this.page = 1;
        } else {
            this.page = page;
        }
    }

    public int page() {
        return page;
    }

    public int pageOf(String str) {
        int index = text.indexOf(str);
        if (index == -1) {
            return -1;
        }
        return (index / 3200) + 1;
    }

    public String text() {
        return text;
    }
}



class Screen extends JPanel implements ActionListener {

    private Core core;
    private LibCipher LibCipher;

    private static final int WIDTH = 880;
    private static final int HEIGHT = 500;

    private JTextArea page;
    private JScrollPane pane;
    private Book currentBook;

    private JButton search, find;

    private JTextArea shelfI, sectionI, indexI, pageI, findI;
    private JScrollPane shelfPane, sectionPane, indexPane, pagePane, findPane;
    private JButton shelfT, sectionT, indexT, pageT, findT, backT;

    private JButton forward, back;
    private JButton backward, front;
    private JButton copy, paste;

    private boolean inMenu;
    private Font c12, c20;

    public Screen(Core core, LibCipher LibCipher) {
        this.setLayout(null);
        this.core = core;
        this.LibCipher = LibCipher;

        // misc.
        c12 = new Font("Courier", Font.PLAIN, 12);
        c20 = new Font("Courier", Font.PLAIN, 20);
        currentBook = new Book(core.bookID(BigInteger.ZERO, 0, 0), LibCipher);
        inMenu = false;

        // PAGE
        page = new JTextArea();
        page.setEditable(false);
        page.setFont(c12);
        pane = new JScrollPane(page, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        pane.setBounds(300, 30, 580, 445);
        this.add(pane);
        page.setCaretPosition(0);

        // INPUTS
        shelfI = new JTextArea(0, 80);
        shelfI.setFont(c12);
        shelfI.setLineWrap(true);
        shelfI.setWrapStyleWord(true);
        shelfPane = new JScrollPane(shelfI, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        shelfPane.setBounds(300, 30, 580, 445);
        this.add(shelfPane);
        shelfI.setCaretPosition(0);
        shelfI.setVisible(false);
        shelfPane.setVisible(false);

        sectionI = new JTextArea(0, 80);
        sectionI.setFont(c12);
        sectionI.setLineWrap(true);
        sectionI.setWrapStyleWord(true);
        sectionPane = new JScrollPane(sectionI, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        sectionPane.setBounds(300, 30, 580, 445);
        this.add(sectionPane);
        sectionI.setCaretPosition(0);
        sectionI.setVisible(false);
        sectionPane.setVisible(false);

        indexI = new JTextArea(0, 80);
        indexI.setFont(c12);
        indexI.setLineWrap(true);
        indexI.setWrapStyleWord(true);
        indexPane = new JScrollPane(indexI, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        indexPane.setBounds(300, 30, 580, 445);
        this.add(indexPane);
        indexI.setCaretPosition(0);
        indexI.setVisible(false);
        indexPane.setVisible(false);

        pageI = new JTextArea(0, 80);
        pageI.setFont(c12);
        pageI.setLineWrap(true);
        pageI.setWrapStyleWord(true);
        pagePane = new JScrollPane(pageI, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        pagePane.setBounds(300, 30, 580, 445);
        this.add(pagePane);
        pageI.setCaretPosition(0);
        pageI.setVisible(false);
        pagePane.setVisible(false);

        findI = new JTextArea(40, 80);
        findI.setFont(c12);
        findI.setLineWrap(true);
        findI.setWrapStyleWord(true);
        findPane = new JScrollPane(findI, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        findPane.setBounds(300, 30, 580, 445);
        this.add(findPane);
        findI.setCaretPosition(0);
        findI.setVisible(false);
        findPane.setVisible(false);

        // TOGGLES
        shelfT = new JButton("Shelf");
        shelfT.setBounds(25, 30, 99, 30);
        shelfT.addActionListener(this);
        this.add(shelfT);
        sectionT = new JButton("Section");
        sectionT.setBounds(25, 70, 99, 30);
        sectionT.addActionListener(this);
        this.add(sectionT);
        indexT = new JButton("Index");
        indexT.setBounds(25, 110, 99, 30);
        indexT.addActionListener(this);
        this.add(indexT);
        pageT = new JButton("Page");
        pageT.setBounds(25, 150, 99, 30);
        pageT.addActionListener(this);
        this.add(pageT);
        findT = new JButton("Find");
        findT.setBounds(25, 190, 100, 30);
        findT.addActionListener(this);
        this.add(findT);
        findT.setVisible(true);
        backT = new JButton("Back");
        backT.setBounds(25, 270, 100, 30);
        backT.addActionListener(this);
        this.add(backT);
        backT.setVisible(false);

        // ACTION
        search = new JButton("Search");
        search.setBounds(25, 230, 99, 30);
        search.addActionListener(this);
        this.add(search);
        search.setVisible(true);
        find = new JButton("Find");
        find.setBounds(160, 30, 100, 30);
        find.addActionListener(this);
        this.add(find);
        find.setVisible(false);

        copy = new JButton("Copy");
        copy.setBounds(160, 30, 99, 30);
        copy.addActionListener(this);
        this.add(copy);
        copy.setVisible(false);
        paste = new JButton("Paste");
        paste.setBounds(160, 70, 99, 30);
        paste.addActionListener(this);
        this.add(paste);
        paste.setVisible(false);

        // NAVIGATION
        forward = new JButton(">");
        forward.setBounds(160, 30, 55, 30);
        forward.addActionListener(this);
        this.add(forward);
        back = new JButton(">>");
        back.setBounds(160, 70, 55, 30);
        back.addActionListener(this);
        this.add(back);

        backward = new JButton("<");
        backward.setBounds(215, 30, 55, 30);
        backward.addActionListener(this);
        this.add(backward);
        front = new JButton("<<");
        front.setBounds(215, 70, 55, 30);
        front.addActionListener(this);
        this.add(front);

        updatePage();
    }
    
    @Override
  	public Dimension getPreferredSize() {
  		return new Dimension(WIDTH, HEIGHT);
  	}
    
    @Override
  	public void paintComponent(Graphics g) {
        super.paintComponent(g);

        if (!inMenu) {
            // draw page #
            g.setFont(c20);
            int pgX = (WIDTH - ((880 - 300) / 2)) - (7 * 7); // page midpoint - (char length * mid # char)
            g.drawString("Page " + currentBook.page(), pgX, 20);

            // draw line indicators
            g.drawLine(336, 480, 336, 485);
            g.drawLine(371, 480, 371, 490);
            g.drawLine(406, 480, 406, 485);
            g.drawLine(441, 480, 441, 495);
            g.drawLine(476, 480, 476, 485);
            g.drawLine(511, 480, 511, 490);
            g.drawLine(546, 480, 546, 485);
            g.drawLine(581, 480, 581, 495);
            g.drawLine(616, 480, 616, 485);
            g.drawLine(651, 480, 651, 490);
            g.drawLine(686, 480, 686, 485);
            g.drawLine(721, 480, 721, 495);
            g.drawLine(756, 480, 756, 485);
            g.drawLine(791, 480, 791, 490);
            g.drawLine(826, 480, 826, 485);
        }

        g.setFont(c12);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == forward) {
            currentBook.flipForward();
            updatePage();
            repaint();
        } else if (e.getSource() == backward) {
            currentBook.flipBackward();
            updatePage();
            repaint();
        }

        else if (e.getSource() == front) {
            currentBook.setPage(1);
            updatePage();
            repaint();
        } else if (e.getSource() == back) {
            currentBook.setPage(410);
            updatePage();
            repaint();
        }

        else if (e.getSource() == search) {

            // get shelf, section, and index
            BigInteger shelfNum = new BigInteger(shelfI.getText());
            int sectionNum = Integer.parseInt(sectionI.getText());
            int bookIndex = Integer.parseInt(indexI.getText());

            // set book and page
            currentBook = new Book(core.bookID(shelfNum, sectionNum, bookIndex), LibCipher);
            if (!pageI.getText().equals("") && !pageI.getText().equals("Page")) {
                currentBook.setPage(Integer.parseInt(pageI.getText()));
            }
            updatePage();

            repaint();
        }

        else if (e.getSource() == find) {

            // get and (if needed) correct page
            int page = -1;
            if (pageI.getText().equals("") || pageI.getText().equals("Page")) {
                page = 1;
            } else {
                page = Integer.parseInt(pageI.getText());
            }
            if (page < 1) {
                page = 1;
            } else if (page > 410) {
                page = 410;
            }

            // check for valid length
            String findITxt = findI.getText();
            if (findITxt.length() > 3200) {
                throw new IllegalArgumentException("Screen.actionPerformed(ActionEvent).findITxt.length() is too large (>3200)");
            }

            // get encrypted base-95 of string
            BigInteger encryptedBase95 = LibCipher.encrypt(LibCipher.toBase95(findITxt));
            
            // get text of encrypted base-95 number
            String text = LibCipher.toText(encryptedBase95);

            // replace text at location with text to find
            int location = encryptedBase95.mod(BigInteger.valueOf(10000)).mod(BigInteger.valueOf(3200 - findITxt.length() )).intValue();
            text = text.substring(0, (3200 * (page - 1)) + location) + findITxt + text.substring((3200 * (page - 1)) + location + findITxt.length());

            // run text through toBase95(String) and decrypt number
            BigInteger newBookID = LibCipher.toBase95(text);

            // set book
            currentBook = new Book(newBookID, LibCipher, "encrypted");

            // get parts and save to respective slots
            BigInteger[] bookIDParts = core.bookLoc(LibCipher.decrypt(newBookID));
            shelfI.setText(bookIDParts[0].toString());
            sectionI.setText(bookIDParts[1].toString());
            indexI.setText(bookIDParts[2].toString());
            
            // set page
            currentBook.setPage(page);
            pageI.setText(page + "");
            updatePage();

            repaint();
        }

        else if (e.getSource() == copy) {
            BigInteger[] bookIDParts = core.bookLoc(currentBook.bookID);
            String shelfITxt = shelfI.getText();
            shelfI.setText(bookIDParts[0].toString());
            shelfI.selectAll();
            shelfI.copy();
            shelfI.setText(shelfITxt);
        } else if (e.getSource() == paste) {
            shelfI.paste();
        }

        else if (e.getSource() == shelfT) {
            defaultVisible();
            shelfI.setVisible(true);
            shelfPane.setVisible(true);
            copy.setVisible(true);
            paste.setVisible(true);

            repaint();
        } else if (e.getSource() == sectionT) {
            defaultVisible();
            sectionI.setVisible(true);
            sectionPane.setVisible(true);

            repaint();
        } else if (e.getSource() == indexT) {
            defaultVisible();
            indexI.setVisible(true);
            indexPane.setVisible(true);

            repaint();
        } else if (e.getSource() == pageT) {
            defaultVisible();
            pageI.setVisible(true);
            pagePane.setVisible(true);

            repaint();
        } else if (e.getSource() == findT) {
            defaultVisible();
            findI.setVisible(true);
            findPane.setVisible(true);
            find.setVisible(true);

            repaint();
        }
        
        else if (e.getSource() == backT) {
            defaultVisible();

            forward.setVisible(true);
            backward.setVisible(true);
            front.setVisible(true);
            back.setVisible(true);

            backT.setVisible(false);

            shelfI.setVisible(false);
            sectionI.setVisible(false);
            indexI.setVisible(false);
            pageI.setVisible(false);

            page.setVisible(true);
            pane.setVisible(true);

            inMenu = false;
            repaint();
        }
    }

    private void defaultVisible() {
        // set default visibilities
        forward.setVisible(false);
        backward.setVisible(false);
        front.setVisible(false);
        back.setVisible(false);
        
        backT.setVisible(true);

        shelfI.setVisible(false);
        sectionI.setVisible(false);
        indexI.setVisible(false);
        pageI.setVisible(false);
        findI.setVisible(false);

        shelfPane.setVisible(false);
        sectionPane.setVisible(false);
        indexPane.setVisible(false);
        pagePane.setVisible(false);
        findPane.setVisible(false);

        find.setVisible(false);
        copy.setVisible(false);
        paste.setVisible(false);
        
        page.setVisible(false);
        pane.setVisible(false);

        inMenu = true;
    }

    private void updatePage() {
        page.setText(currentBook.read());
        page.setCaretPosition(0);
    }
}



public class Library {
    public static void main(String[] args) {
        Amount a = new Amount();

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("The Library");
            Screen screen = new Screen(new Core(), new LibCipher(a.BOOK_AMOUNT));
            frame.add(screen);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.pack();
            frame.setVisible(true);
        });
    }
}
