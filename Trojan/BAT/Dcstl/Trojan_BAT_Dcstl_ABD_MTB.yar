
rule Trojan_BAT_Dcstl_ABD_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 08 08 16 08 8e 69 6f 90 01 03 0a 00 11 08 6f 90 01 03 0a 00 06 13 09 11 09 07 28 90 01 03 2b 28 90 01 03 2b 13 09 11 09 11 07 6f 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 13 09 11 07 6f 90 01 03 0a 00 11 08 6f 90 01 03 0a 00 11 09 28 90 01 03 0a 13 0a de 3f 90 00 } //01 00 
		$a_01_1 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {41 00 6e 00 74 00 69 00 20 00 48 00 54 00 54 00 50 00 20 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //00 00  Anti HTTP Debugger
	condition:
		any of ($a_*)
 
}