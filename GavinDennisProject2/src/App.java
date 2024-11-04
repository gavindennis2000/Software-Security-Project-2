// Gavin Dennis
// CS 3780
// Project 2
// Due 2024 November 3

import java.io.File;  // for file handling
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;  // for exception handling when writing to files
import java.io.PrintWriter;  // for writing to files
import java.io.UnsupportedEncodingException;
import java.util.Scanner;  // for user input and file reading
import java.util.regex.Matcher;  // for username/password pattern checking
import java.util.regex.Pattern;  // for username/password pattern checking
import java.security.MessageDigest;  // for password hashing
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class App {
    public static void cPrint(String str) {
        // c-style print function for easier screen logging

        System.out.println(str);
    }

    public static void login() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // handles login by getting user input and validating with all three password files

        Scanner input = new Scanner(System.in);  // scanner for user input

        String userInput;  // string for inputted username
        String pwInput;  // string for inputted password
        String userFromFile = "";  // string for validating username from password files
        String pwFromFile = "";  // string for validating username from password files

        int lineNumber = 0;  // line number to ensure password is connected to correct username

        String [] passwordFiles = new String[] {"plaintext.txt", "hashed.txt", "salt.txt"};
        boolean [] validationArr = new boolean[] {false, false, false};  // array of booleans for validating each password file

        // get username attempt from user
        cPrint("Enter username: ");
        userInput = input.nextLine();

        // get password attempt from user
        cPrint("Enter password: ");
        pwInput = input.nextLine();

        // close the scanner
        input.close();

        // validate username and password
        for (int i = 0; i < 3; i++) {
            lineNumber = 0;
            userFromFile = "";
            try {

                // open password file and search each line for matching username
                Scanner file = new Scanner(new File(passwordFiles[i]));

                while (!userFromFile.equals(userInput) && file.hasNextLine()) {
                    lineNumber++;

                    // only check odd number lines for usernames as the even ones will have passwords
                    if (lineNumber % 2 == 0) { continue; }
                    else { userFromFile = file.nextLine(); }
                }

                // validate the username for the given file if it checks out
                if (userFromFile.equals(userInput)) {

                    // attempt to validate the password
                    pwFromFile = file.nextLine();
                    // cPrint(pwInput + " and " + pwFromFile);

                    if (i == 0) {  // validate plaintext password
                        if (pwFromFile.equals(pwInput)) { validationArr[i] = true; }
                        else { cPrint("Failed at " + i); }
                    }
                    else if (i == 1) {  // validate hashed password
                        // hash inputted password
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                        String pw = "password";
                        byte [] hashedPassword = messageDigest.digest(pw.getBytes("UTF-8"));
                        pwInput = hashedPassword.toString();

                        // compare hashed input password to file password
                        if (pwFromFile.equals(pwInput)) { validationArr[i] = true; }
                        else { cPrint("Failed at " + i); cPrint(pwInput + " and " + pwFromFile);}
                    }
                    else if (i == 2) {  // validate hashed+salt password
                        // salt
                        String salt = pwFromFile;

                        // compare hashed+salted input password to file password
                        if (pwFromFile.equals(pwInput+salt)) { validationArr[i] = true; }
                        else { cPrint("Failed at " + i + ". input: " + pwInput+salt + " file: " + pwFromFile); }
                    }
                }

                // close the file
                file.close();
            } 
            catch (FileNotFoundException e) {
                cPrint("ERROR: Unable to validate password; No password file.");
                e.printStackTrace();
            }
        }

        // check if all validations passed
        if (validationArr[0] && validationArr[1] && validationArr[2]) {
            cPrint("Login success.\n");
        }
        else {
            // if validation fails, retry login function
            cPrint("ERROR: Invalid username or password. Please try again.\n");
        }
    }

    public static void createAccount() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        /* handles account creation by getting user input, validating
        with string length, regex pattern checking, and string comparison,
        then attempts to write to file with writeDataToFiles function */

        Scanner input = new Scanner(System.in);  // scanner for user input

        String unAttempt;  // a string that contains the user's inputted username attempt;
        String pwAttempt;  // a string that contains the user's inputted password attempt;

        String username = "";  // a string that contains the user's validated ID; 5-10 character length with only alphabetic characters
        String password = "";  // a string that contains the user's validated password; only lowercase alphabetic characters

        String repeat;  // compared to password to make sure they match
        
        Pattern unPattern = Pattern.compile("^[a-zA-Z]+$");  // regex pattern for validating inputted username
        Pattern pwPattern = Pattern.compile("^[a-z]+$");  // regex pattern for validating inputted password

        int minSize = 5, maxSize = 10;  // integers to validate size of username and password attempts

        boolean usernameValidation = false;  // boolean to loop input while input isn't valid
        boolean passwordValidation = false;  // boolean to loop input while input isn't valid
        
        // message to user to explain username input
        cPrint(
            ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . " +
            "\nCreate an Account\n"
        );
        cPrint(
            "* * * * * Username * * * * *\n" + 
            "Username must be 5-10 characters in length and only use alphabetic characters [a-z] and [A-Z]." + 
            "Please enter your new username: "
        );

        // get input from user and validate
        while (!usernameValidation) {
            
            // get username string
            unAttempt = input.nextLine();

            // validate username input
            // first check the string length
            if (unAttempt.length() <= maxSize && unAttempt.length() >= minSize) {
                // if string length checks out, run the regex matcher
                Matcher matcher = unPattern.matcher(unAttempt);
                if (matcher.matches()) {
                    // assign the validated strinmjg to username
                    usernameValidation = true;
                    username = unAttempt;
                }
                else {
                    cPrint("\nInput contains non-alphabetic characters. \nPlease try again. \n");
                }
            }
            else { 
                cPrint(
                    "\nUsername is not within specified length limit (5-10 characters).\n" + 
                    "Please try again. \n"
                );
            }
        }

        // print out username validation message
        cPrint("\nUsername successfully validated.\n");

        // get password from user

        // message to user to explain password input
        cPrint(
            "* * * * * Password * * * * *\n" + 
            "Password must be 5-10 characters in length and only use lowercase alphabetic characters [a-z]." +
            "Please enter your password: "
        );

        // get input from user and validate
        while (!passwordValidation) {
            
            // get password string
            pwAttempt = input.nextLine();

            // validate password input
            // make sure the password isn't the same as the username
            if (pwAttempt.equals(username)) {
                cPrint("\nPassword cannot be the same as username. \n" + "Please try again. \n" + "\nPlease enter your password: ");
            }
            // check the string length
            else if (pwAttempt.length() <= maxSize && pwAttempt.length() >= minSize) {
                // if string length checks out, run the regex matcher
                Matcher matcher = pwPattern.matcher(pwAttempt);
                if (matcher.matches()) {
                    // prompt user for password confirmation
                    cPrint("\nConfirm password: ");
                    repeat = input.nextLine();

                    // check if password input is the same confirmation
                    if (pwAttempt.equals(repeat)) { 
                        passwordValidation = true; 
                        password = pwAttempt;
                    }
                    else {
                        cPrint("\nPasswords do not match. \n" + "Please try again. \n" + "\nPlease enter your password: ");
                    }
                }
                else {
                    cPrint("\nInput contains non-alphabetic characters or capital letters. \nPlease try again. \n");
                }
            }
            else { 
                cPrint(
                    "\nPassword is not within specified length limit (5-10 characters).\n" + 
                    "Please try again. \n"
                );
            }
        }

        cPrint("\nPassword successfully validated. Attempting to write to files");

        // end the function by closing the scanner and attempting to write the data to 3 password files
        input.close();
        writeDataToFiles(username, password);
    }

    public static void writeDataToFiles(String username, String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        /* takes validated username and password as arguments and writes them to three files 
            1. plaintext username password pair
            2. username and hashed password
            3. username, salt, and hashed (password + salt)
        */

        // get hash and salt
        // hash
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte [] hashedPassword = messageDigest.digest(password.getBytes("UTF-8"));

        // salt
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[1];
        random.nextBytes(salt);

        // try writing to file
        try {
            FileWriter plainText = new FileWriter("plaintext.txt", true);
            FileWriter hashText = new FileWriter("hashed.txt", true);
            FileWriter saltText = new FileWriter("salt.txt", true);

            // write to files
            plainText.write(username + "\n" + password + "\n");  // plaintext password
            hashText.write(username + "\n" + hashedPassword + "\n");  // hashed password
            saltText.write(username + "\n" + hashedPassword + salt + "\n");  // hashed with salt

            // close the file writers
            plainText.close();
            hashText.close();
            saltText.close();
        }
        catch(IOException e) {
            System.out.println("ERROR: Couldn't print to file.");
            e.printStackTrace();
        }
        System.out.println("Output to files successful.");
    }

    public static void main(String[] args) throws Exception {
        // prompt user for function: login or create account
        Scanner input = new Scanner(System.in);

        int choice = -1;
        while (choice != 1 && choice != 2 && choice != 3) {
            cPrint(
                "Choose an option: \n" + 
                "\t1: Login\n" + 
                "\t2: Create an Account\n" + 
                "\t3: Exit program"
            );
            choice = input.nextInt();

            if (choice != 1 && choice != 2 && choice != 3) {
                cPrint("Please select '1', '2', or '3' and press enter.\n");
            }
        }

        // call whichever function the user has picked
        if (choice == 1) { login(); }
        else if (choice == 2) { createAccount(); }

        // terminate the program
        input.close();  // close the scanner
        System.exit(0);
    }
}
