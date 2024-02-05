
rule Trojan_Win32_VBcrypt_WSG_MTB{
	meta:
		description = "Trojan:Win32/VBcrypt.WSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 65 6d 69 75 72 67 65 73 31 } //01 00 
		$a_81_1 = {43 61 6c 6c 6f 73 69 74 69 65 73 33 } //01 00 
		$a_81_2 = {41 63 63 72 65 74 69 6f 6e 61 72 79 } //01 00 
		$a_81_3 = {42 6c 61 6e 64 69 73 68 6d 65 6e 74 } //01 00 
		$a_01_4 = {65 00 6c 00 77 00 6a 00 6e 00 7a 00 6c 00 68 00 69 00 67 00 6b 00 61 00 } //01 00 
		$a_01_5 = {64 00 6b 00 7a 00 7a 00 69 00 6f 00 78 00 67 00 75 00 } //00 00 
	condition:
		any of ($a_*)
 
}