
rule Trojan_BAT_DSCStealer_MCT_MTB{
	meta:
		description = "Trojan:BAT/DSCStealer.MCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6f 4e 6f 74 54 72 79 5f 4c 68 76 67 44 52 4b 52 4f 6b 62 4f 6e 68 75 70 4e 55 4f 43 64 56 65 4e 77 61 50 74 66 61 4a 7a 6b 4e 44 79 64 7a 4b 78 4f 41 54 50 4a 57 49 } //1 DoNotTry_LhvgDRKROkbOnhupNUOCdVeNwaPtfaJzkNDydzKxOATPJWI
		$a_01_1 = {44 6f 4e 6f 74 54 72 79 5f 41 53 67 63 46 7a 7a 68 69 67 64 66 70 } //1 DoNotTry_ASgcFzzhigdfp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}