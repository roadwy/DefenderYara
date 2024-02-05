
rule Trojan_Win32_VBKrypt_BQ_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {4a 75 6e 6b 20 50 72 6f 67 72 61 6d 73 } //01 00 
		$a_81_1 = {44 65 62 75 67 67 79 20 42 79 20 56 61 6e 6a 61 20 46 75 63 6b 61 72 } //01 00 
		$a_81_2 = {46 6f 72 20 48 61 63 6b 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}