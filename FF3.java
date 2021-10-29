import java.io.BufferedReader;
import java.io.InputStreamReader;

public class FF3 {

	public static void main(String[] args) {
		try {
		   BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		   System.out.println("Enter the following options:\n 1 for Encryption followed by Decryption \n 2 for Encryption \n 3 for Decryption\n");
		   int option = Integer.parseInt(reader.readLine());
		   FF3Cipher c=new FF3Cipher("EF78909876543234","9034067899876543");
		   switch(option) {
		       case 1:
		          System.out.println("Enter the plain text of size 16  and hit enter:");
		          String input1 = reader.readLine();
			  String ciphertext1=c.encrypt(input1);
			  System.out.println("Ciphertext:" + ciphertext1); 
			  String plaintext1 = c.decrypt(ciphertext1);
			  System.out.println("Plaintext:" + plaintext1);
			  break;
		      case 2:
		         System.out.println("Enter the plain text of size 16 and hit enter:");
		          String input2 = reader.readLine();
			  String ciphertext2=c.encrypt(input2);
			  System.out.println("Ciphertext:" + ciphertext2);
			  break;
	             case 3:
	                 System.out.println("Enter the cipher text of size 16 and hit enter:");
		          String input3 = reader.readLine();
			  String plaintext3=c.decrypt(input3);
			  System.out.println("Plaintext:" + plaintext3);
			  break;
	            default: break;
	           }
		}catch(Exception e) {
			System.out.println(e);
		}

	}

}
