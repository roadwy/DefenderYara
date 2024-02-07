
rule Trojan_BAT_Bladabindi_MF_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {74 00 64 00 67 00 6d 00 2e 00 65 00 78 00 65 00 } //05 00  tdgm.exe
		$a_01_1 = {73 00 65 00 78 00 79 00 } //05 00  sexy
		$a_01_2 = {4f 51 56 77 75 2e 64 6c 6c } //05 00  OQVwu.dll
		$a_01_3 = {57 4c 6d 51 75 00 66 77 73 72 4d 2e 64 6c 6c 00 76 67 4d 62 69 00 67 42 66 53 47 00 59 56 57 63 75 00 71 47 4f 78 47 00 42 4b 77 65 47 00 54 75 47 41 52 } //01 00 
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //01 00  SELECT * FROM AntivirusProduct
		$a_01_5 = {53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //00 00  Screenshot
	condition:
		any of ($a_*)
 
}