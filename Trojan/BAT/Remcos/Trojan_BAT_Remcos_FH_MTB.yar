
rule Trojan_BAT_Remcos_FH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 14 00 "
		
	strings :
		$a_03_0 = {07 08 06 09 93 9d 00 08 17 58 0c 09 17 59 0d 08 02 6f 90 01 03 0a fe 04 13 04 11 04 2d e1 90 00 } //01 00 
		$a_81_1 = {00 61 61 61 61 61 61 61 00 } //01 00 
		$a_81_2 = {52 65 76 65 72 73 65 53 74 75 66 66 } //01 00  ReverseStuff
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_81_5 = {43 6f 6d 70 72 65 73 73 } //00 00  Compress
	condition:
		any of ($a_*)
 
}