
rule Trojan_Win32_FileCryptor_BL_MTB{
	meta:
		description = "Trojan:Win32/FileCryptor.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 63 72 79 70 74 5c 74 6d 70 5f 90 02 10 5c 90 02 10 2e 70 64 62 90 00 } //01 00 
		$a_00_1 = {57 72 69 74 65 54 61 70 65 6d 61 72 6b } //0a 00 
		$a_03_2 = {6a 65 66 a3 90 01 04 58 6a 72 66 a3 90 01 04 58 6a 6e 66 a3 90 01 04 58 6a 65 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 33 66 a3 90 01 04 58 6a 32 66 a3 90 01 04 58 6a 2e 66 a3 90 01 04 58 6a 64 66 a3 90 01 04 58 6a 6c 90 00 } //0a 00 
		$a_00_3 = {30 04 3e 89 75 80 b8 01 00 00 00 83 f0 04 83 6d 80 01 8b 75 80 3b f3 7d e2 } //00 00 
		$a_00_4 = {5d 04 00 00 f1 45 04 80 5c 26 00 } //00 f2 
	condition:
		any of ($a_*)
 
}