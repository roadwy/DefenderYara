
rule Trojan_Win32_Guloader_RPT_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 64 65 6c 65 5c 57 68 69 73 6b 79 65 6e 73 } //01 00 
		$a_01_1 = {45 78 63 75 72 76 61 74 75 72 65 5c 53 63 61 70 75 6c 61 72 65 2e 64 65 70 } //01 00 
		$a_01_2 = {4e 75 62 69 67 65 6e 6f 75 73 5c 4e 6f 6e 63 72 79 73 74 61 6c 6c 69 73 61 62 6c 65 2e 4b 69 6b } //01 00 
		$a_01_3 = {4f 74 74 65 63 79 6c 69 6e 64 72 65 74 5c 53 68 61 6d 70 6f 6f 65 72 73 35 34 2e 53 76 61 } //01 00 
		$a_01_4 = {50 6e 65 75 6d 6f 6e 65 63 74 6f 6d 79 } //01 00 
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 52 61 70 70 69 6e 69 32 30 30 5c 4b 6c 61 67 65 72 65 74 74 65 72 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 2c 1a 90 9b 31 2c 18 9b 90 81 34 18 } //00 00 
	condition:
		any of ($a_*)
 
}