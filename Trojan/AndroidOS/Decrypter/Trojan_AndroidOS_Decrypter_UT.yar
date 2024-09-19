
rule Trojan_AndroidOS_Decrypter_UT{
	meta:
		description = "Trojan:AndroidOS/Decrypter.UT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 73 54 4d 74 42 33 72 74 52 33 67 37 38 61 5a 32 64 4b 30 7a 33 6d 46 51 61 31 6b 6d 41 41 4a 4d 63 66 6a 32 6a 4f 53 45 } //1 zsTMtB3rtR3g78aZ2dK0z3mFQa1kmAAJMcfj2jOSE
		$a_01_1 = {73 65 6e 64 50 68 6f 74 6f 46 65 65 64 62 61 63 6b 3a 3a 75 72 6c 3a } //1 sendPhotoFeedback::url:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}