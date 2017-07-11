import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;
class DataEncryptionStandard {
    private static final byte[] firstPerm = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    private static final byte[] lastPerm = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
    private static final byte[] selectionTable = {32, 1,  2,  3,  4,  5, 4,  5,  6,  7,  8,  9, 8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
    private static final byte[][] staticTable = {{
        14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7, 0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8, 4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0, 15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13}, {
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10, 3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5, 0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15, 13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9}, {
        10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8, 13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1, 13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7, 1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12}, {
        7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15, 13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9, 10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4, 3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14}, {
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9, 14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6, 4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14, 11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3}, {
        12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11, 10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8, 9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6, 4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13}, {
        4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1, 13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6, 1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2, 6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12}, {
        13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7, 1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2, 7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8, 2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11} };
    private static final byte[] permTable = {16, 7,  20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10, 2,  8,  24, 14, 32, 27, 3,  9, 19, 13, 30, 6, 22, 11, 4,  25};
    private static final byte[] firstTest = {57, 49, 41, 33, 25, 17, 9, 1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
    private static final byte[] secondTest = {14, 17, 11, 24, 1,  5, 3,  28, 15, 6,  21, 10, 23, 19, 12, 4,  26, 8, 16, 7,  27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
    private static final byte[] alteration = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    private static long firstPerm(long origin)
    {return modify(firstPerm, 64, origin);}
    private static long lastPerm(long origin)
    {return modify(lastPerm, 64, origin);}
    private static long selectionTable(int origin)
    {return modify(selectionTable, 32, origin& 0xffffffffL);}
    private static int  permTable(int origin)
    {return (int)modify(permTable, 32, origin& 0xffffffffL);}
    private static long firstTest(long origin)
    {return modify(firstTest, 64, origin);}
    private static long secondTest(long origin)
    {return modify(secondTest, 56, origin);}
    private static long modify(byte[] staticBytes, int originEnd, long origin) {
        long movement = 0;
        for (byte staticByte : staticBytes) {int originStart = originEnd - staticByte; movement = (movement << 1) | (origin >> originStart & 0x01);}
        return movement;}
    private static byte staticTable(int testInt, byte origin) {
        origin = (byte) (origin&0x20 | ((origin&0x01)<<4) | ((origin&0x1E)>>1));
        return staticTable[testInt-1][origin];}
    private static long afromB(byte[] byteAlgo, int change) {
        long a = 0;
        for (int g=0; g<8; g++) {byte result; if ((change+g) < byteAlgo.length) {result = byteAlgo[change+g];}
        else {result = 0;} a = a<<8 | (result & 0xffL);} return a;}
    private static void bfromA(byte[] byteAlgo, int change, long a) {
        for (int g=7; g>=0; g--) {if ((change+g) < byteAlgo.length) {byteAlgo[change+g] = (byte) (a & 0xff); a = a >> 8;}
        else {break;}}}
    private static int alloc(int n, long secMast) {
        long expr = selectionTable(n); long z = expr ^ secMast; int movement = 0;
        for (int g=0; g<8; g++) {movement>>>=4; int q = staticTable(8-g, (byte)(z&0x3F)); movement |= q << 28; z >>= 6;}
        return permTable(movement);}
    private static long[] makeMast(long mast) {
        long secMasts[] = new long[16]; mast = firstTest(mast); int p = (int) (mast>>28); int k = (int) (mast& 0xfffffff);
        for (int g=0; g<16; g++) {
            if (alteration[g] == 1) {p = ((p<<1) & 0xfffffff) | (p>>27); k = ((k<<1) & 0xfffffff) | (k>>27);}
            else {p = ((p<<2) & 0xfffffff) | (p>>26); k = ((k<<2) & 0xfffffff) | (k>>26);}
            long cd = (p& 0xffffffffL)<<28 | (k& 0xffffffffL); secMasts[g] = secondTest(cd);}
            return secMasts;}
    private static long makeSec(long m, long mast) {
        long[] secMasts = makeMast(mast);
        long firstperm = firstPerm(m); int a = (int) (firstperm>>32); int n = (int) (firstperm& 0xffffffffL);
        for (int g=0; g<16; g++) {int previous_l = a; a = n; n = previous_l ^ alloc(n, secMasts[g]);}
        long rl = (n& 0xffffffffL)<<32 | (a& 0xffffffffL); return lastPerm(rl);}
    private static void makeSec(
            byte[] solution, int solutionAlt, byte[] messEncrypt, int messEncryptOffset, byte[] mast)
        {long m = afromB(solution, solutionAlt); long k = afromB(mast, 0); long p = makeSec(m, k);
            bfromA(messEncrypt, messEncryptOffset, p);}
    private static byte[] encrypt(byte[] solution, byte[] mast) {
        byte[] messEncrypt = new byte[solution.length];
        for (int g=0; g<solution.length; g+=8) {makeSec(solution, g, messEncrypt, g, mast);}
        return messEncrypt;}
    private static byte[] unwrap(String password) {
        byte[] ident = password.getBytes(); byte[] mast = new byte[8];
        for (int g=0; g<8; g++) {if (g < ident.length) {byte anon = ident[g]; byte anonAlt = 0;
                for (int t=0; t<8; t++) {anonAlt<<=1; anonAlt |= (anon&0x01); anon>>>=1;} mast[g] = anonAlt;}
                else {mast[g] = 0;}}
        return mast;}
    private static String hex(byte[] unit) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : unit) {sb.append(String.format("%02X ", aByte));}
        return sb.toString();}
	private static String toHex(String arg) throws Exception {
	return String.format("%020x", new BigInteger(1, arg.getBytes("UTF-8")));}
    public static void main(String[] peram) {
        JFrame frame = new JFrame("DES Encryption");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        JPanel contentPane = new JPanel();
        contentPane.setOpaque(true);
        contentPane.setBackground(Color.WHITE);
        contentPane.setLayout(null);
        JLabel headerLabel = new JLabel("56-Bit DES Encryption");
        headerLabel.setSize(1000, 300);
        headerLabel.setLocation(300, 35);
		headerLabel.setFont(new Font("Times New Roman", Font.BOLD, 20));
        JLabel messageLabel = new JLabel("Enter the Message to be Encrypted");
        messageLabel.setSize(1000, 280);
        messageLabel.setLocation(100, 150);
		messageLabel.setFont(new Font("Serif", Font.BOLD, 18));
        JTextField messageTextField = new JTextField("",3);
		messageTextField.setSize(200,50);
		messageTextField.setLocation(450,270);
        JLabel keyLabel = new JLabel("Enter The Key");
        keyLabel.setSize(1000, 280);
        keyLabel.setLocation(100, 230);
		keyLabel.setFont(new Font("Serif", Font.BOLD, 18));
        JTextField keyTextField = new JTextField("",3);
		keyTextField.setSize(200,50);
		keyTextField.setLocation(450,350);
        JButton button = new JButton("ENCRYPT");
        button.setSize(100, 30);
        button.setLocation(350, 450);
        JLabel hexMessageLabel = new JLabel("Message In HexaDecimal");
        hexMessageLabel.setSize(1000, 280);
        hexMessageLabel.setLocation(100, 400);
		hexMessageLabel.setFont(new Font("Serif", Font.BOLD, 18));
		hexMessageLabel.setVisible(false);
        JLabel hexMessageValueLabel = new JLabel("Enter ");
        hexMessageValueLabel.setSize(1000, 280);
        hexMessageValueLabel.setLocation(500, 400);
		hexMessageValueLabel.setFont(new Font("Serif", Font.BOLD, 18));
		hexMessageValueLabel.setVisible(false);
        JLabel hexKeyLabel = new JLabel("Key In Hexadecimal");
        hexKeyLabel.setSize(1000, 280);
        hexKeyLabel.setLocation(100, 450);
		hexKeyLabel.setFont(new Font("Serif", Font.BOLD, 18));
		hexKeyLabel.setVisible(false);
        JLabel hexKeyValueLabel = new JLabel("Enter");
        hexKeyValueLabel.setSize(1000, 280);
        hexKeyValueLabel.setLocation(500, 450);
		hexKeyValueLabel.setFont(new Font("Serif", Font.BOLD, 18));
		hexKeyValueLabel.setVisible(false);
        JLabel encryptedMessageLabel = new JLabel("Encrypted Message");
        encryptedMessageLabel.setSize(1000, 280);
        encryptedMessageLabel.setLocation(100, 500);
		encryptedMessageLabel.setFont(new Font("Serif", Font.BOLD, 18));
		encryptedMessageLabel.setVisible(false);
        JLabel encryptedValueLabel = new JLabel("Enter the Message to be Encrypted");
        encryptedValueLabel.setSize(1000, 280);
        encryptedValueLabel.setLocation(500, 500);
		encryptedValueLabel.setFont(new Font("Serif", Font.BOLD, 18));
		encryptedValueLabel.setVisible(false);
        button.addActionListener(e -> {
            try {
                String message = messageTextField.getText();
                String hexMessage = toHex(message);
                byte[] byteMessage = new BigInteger(hexMessage,16).toByteArray();
                String key = keyTextField.getText();
                byte[] byteKey = unwrap(key);
                String hexKey = hex(byteKey);
                byte[] cypherText = encrypt(byteMessage,byteKey);
                String hexReceived = hex(cypherText);
                hexMessageLabel.setVisible(true);
                hexMessageValueLabel.setVisible(true);
                hexKeyLabel.setVisible(true);
                hexKeyValueLabel.setVisible(true);
                encryptedMessageLabel.setVisible(true);
                encryptedValueLabel.setVisible(true);
                hexMessageValueLabel.setText(hexMessage);
                hexKeyValueLabel.setText(hexKey);
                encryptedValueLabel.setText(hexReceived);}
            catch(Exception e1) {e1.printStackTrace();}});
        contentPane.add(headerLabel);
		contentPane.add(messageLabel);
		contentPane.add(keyLabel);
		contentPane.add(messageTextField);
		contentPane.add(keyTextField);
		contentPane.add(hexMessageLabel);
		contentPane.add(hexMessageValueLabel);
		contentPane.add(hexKeyValueLabel);
		contentPane.add(hexKeyLabel);
		contentPane.add(encryptedMessageLabel);
		contentPane.add(encryptedValueLabel);
        contentPane.add(button);
        frame.setContentPane(contentPane);
        frame.setSize(1000, 1000);
        frame.setLocationByPlatform(true);
        frame.setVisible(true);}}