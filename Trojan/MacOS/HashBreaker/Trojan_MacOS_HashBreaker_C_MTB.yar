
rule Trojan_MacOS_HashBreaker_C_MTB{
	meta:
		description = "Trojan:MacOS/HashBreaker.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 75 6d 70 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 73 } //1 dump-generic-passwords
		$a_01_1 = {65 73 72 63 2f 6d 61 69 6e 2e 72 73 47 65 74 20 70 61 73 73 77 6f 72 64 } //1 esrc/main.rsGet password
		$a_01_2 = {70 75 6e 6c 6f 63 6b 2d 6b 65 79 63 68 61 69 6e } //1 punlock-keychain
		$a_01_3 = {69 6e 6a 65 63 74 69 6e 67 2f 44 6f 63 75 6d 65 6e 74 73 2f 41 64 64 6f 6e 73 2e 7a 69 70 } //1 injecting/Documents/Addons.zip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}