/**
 * @displayName jBCrypt
 * @hint A ColdFusion component that provides an interface to the jBCrypt Java library for hashing and verifying passwords.
 * This component follows modern security best practices by relying on jBCrypt's internal salt generation.
 */
component {

	/**
	 * @hint Constructor: Initializes the jBCrypt component.
	 */
	public jBCrypt function init() {
		// Create an instance of the jBCrypt Java object.
		variables.oBCrypt = createObject("java", "org.mindrot.jbcrypt.BCrypt");
		return this;
	}

	/**
	 * @hint Hashes a password using bcrypt.
	 * @inPasswordToHash The password string to hash.
	 * @inBCryptWorkFactor The log_rounds parameter for bcrypt, determining the computational cost. Default is 10.
	 * @return Returns the hashed password string.
	 */
	public string function hashpw(required string inPasswordToHash, numeric inBCryptWorkFactor = 10) {
		// The work factor must be an integer between 10 and 31.
		if (isValid("integer", arguments.inBCryptWorkFactor) && arguments.inBCryptWorkFactor GTE 10) {
			/*
			 * SECURITY NOTE:
			 * The previous implementation used a custom, hardcoded salt. This is a significant security flaw.
			 * The proper use of bcrypt, as implemented here, is to let the library generate a random salt for each password.
			 * This salt is then stored as part of the resulting hash string, ensuring that each password has a unique salt.
			 */
			return variables.oBCrypt.hashpw(arguments.inPasswordToHash, variables.oBCrypt.genSalt(arguments.inBCryptWorkFactor));
		} else {
			throw(type="Invalid Work Factor", message="The work factor must be a valid positive integer no smaller than 10.");
		}
	}

	/**
	 * @hint Verifies a plaintext password against a bcrypt hash.
	 * @inString The plaintext password to check.
	 * @inCryptedString The bcrypt hash to check against.
	 * @return Returns true if the password matches the hash, otherwise false.
	 */
	public boolean function checkHash(required string inString, required string inCryptedString) {
		try {
			// The checkpw function handles extracting the salt from the hash and comparing the password.
			return variables.oBCrypt.checkpw(arguments.inString, arguments.inCryptedString);
		} catch (any e) {
			// If jbcrypt throws an error (e.g., invalid hash format), return false.
			return false;
		}
	}
}
