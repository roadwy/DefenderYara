
rule Trojan_BAT_Stelega_DL_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 69 6e 65 53 77 65 65 70 65 72 5f 4a 53 4a } //01 00  MineSweeper_JSJ
		$a_81_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_2 = {73 6d 69 6c 65 20 77 69 6e } //01 00  smile win
		$a_81_3 = {67 65 74 5f 58 } //01 00  get_X
		$a_81_4 = {67 65 74 5f 59 } //01 00  get_Y
		$a_81_5 = {2e 4c 6f 63 6b 65 64 } //00 00  .Locked
	condition:
		any of ($a_*)
 
}