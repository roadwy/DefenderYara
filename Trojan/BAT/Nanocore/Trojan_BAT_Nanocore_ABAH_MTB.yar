
rule Trojan_BAT_Nanocore_ABAH_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {18 9a 0a 06 6f 90 01 03 0a 19 9a 0b 07 16 8c 90 01 03 01 19 8d 90 01 03 01 25 16 28 90 01 03 06 6f 90 01 03 06 6f 90 01 03 06 a2 25 17 28 90 01 03 06 6f 90 01 03 06 6f 90 01 03 06 a2 25 18 72 90 01 03 70 a2 6f 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {49 00 6e 00 73 00 74 00 61 00 67 00 72 00 61 00 6d 00 5f 00 54 00 61 00 6b 00 65 00 6f 00 75 00 74 00 5f 00 50 00 61 00 72 00 73 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Instagram_Takeout_Parser.Resources
		$a_01_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //01 00  download
		$a_01_3 = {72 00 65 00 64 00 5f 00 6c 00 6f 00 76 00 65 00 } //00 00  red_love
	condition:
		any of ($a_*)
 
}