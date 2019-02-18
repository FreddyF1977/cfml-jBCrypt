component displayname="jBCrypt" output="false" hint="Generate hash with jBCrypt" {
    /**
	* @hint Constructor
	*/	
	public jBCrypt function init() {
        variables.StoredSalt = "-------Salt-------";
        variables.oBCrypt = createObject("java", "org.mindrot.jbcrypt.BCrypt");;
	
		return this;
	}

	/**
	* @hint Will hash a string
	* @inPasswordToHash The string that will be hashed
	* @inBCryptWorkFactor object, binary or string 
	*/	
	public string function hashps(required string inPasswordToHash, numeric inBCryptWorkFactor = 10) {
        var passwordToHash = salt(arguments.inPasswordToHash);

        if (isValid("integer", arguments.inBCryptWorkFactor) && arguments.inBCryptWorkFactor GTE 10){

            /*
                hashpw use 18 4 bytes integer to XOR the password
                so only the first 72 bytes are important.  Padding it with the username and internal salt
                only help for small password.
                Common guideline are to silently ignore everything after the 72th character.
                A 72 characters bCrypted password is VERY likely to be unique and we have to match it
                to the username anyway (which is always unique).
            */

            return variables.oBCrypt.hashpw(passwordToHash, variables.oBCrypt.genSalt(arguments.inBCryptWorkFactor));
        } else {
            throw(type="Invalid Work Factor", message="The work factor must be a valid positive integer no smaller than 10");
        }
	}

	/**
	* @hint Append salt to the string
	* @inString The string that will be hashed
	*/	
	public string function salt(required string inString) {
       //Don't reverse this, the most important bytes should be FIRST, the rest is padding for weak password
       return arguments.inString & variables.StoredSalt;
	}

	/**
	* @hint Verify the string agains the hash
	* @inString The string that will be hashed
	* @inCryptedString The crypted string against what the hash will be tested	
    */	
	public string function checkHash(required string inString, required string inCryptedString) {
        var stringToHash = saltPassword(arguments.inString);

        if (len(stringToHash) && len(arguments.inCryptedString)){
            return variables.oBCrypt.checkpw(stringToHash, arguments.inCryptedString) ? "SUCCESS" : "FAIL";
        } else {
            return "FAIL";
        }
	}
}