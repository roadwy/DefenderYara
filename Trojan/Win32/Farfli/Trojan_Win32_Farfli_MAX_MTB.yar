
rule Trojan_Win32_Farfli_MAX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 59 72 65 65 6e 51 69 6c 6c 6e 39 37 76 71 7a } //0a 00 
		$a_01_1 = {90 32 65 90 df 04 7c 5d 5b 0b 5e 78 db 21 a9 4a 24 78 23 23 76 2d 41 66 5f 76 65 58 71 42 ca 1e } //01 00 
		$a_01_2 = {2e 76 6d 70 73 30 } //01 00 
		$a_01_3 = {2e 76 6d 70 73 31 } //01 00 
		$a_01_4 = {51 75 65 72 79 46 75 6c 6c 50 72 6f 63 65 73 73 49 6d 61 67 65 4e 61 6d 65 57 } //01 00 
		$a_01_5 = {57 54 53 53 65 6e 64 4d 65 73 73 61 67 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}