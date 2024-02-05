
rule Trojan_Win32_Farfli_DAS_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c7 6a 03 99 59 f7 f9 83 fa 02 75 06 8a 45 f8 28 04 37 83 fa 01 75 06 8a 45 f4 28 04 37 3b d3 75 09 8a 45 f4 02 45 f8 28 04 37 47 3b 7d fc 7c } //02 00 
		$a_01_1 = {ff d7 6a 1a 99 59 f7 f9 8b 4d 08 8a 44 15 e4 88 04 0e 46 3b f3 7c } //01 00 
		$a_01_2 = {65 6b 69 6d 68 75 71 63 72 6f 61 6e 66 6c 76 7a 67 64 6a 74 78 79 70 73 77 62 } //01 00 
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 } //01 00 
		$a_01_4 = {63 3a 5c 25 73 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}