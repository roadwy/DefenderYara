
rule Trojan_BAT_AveMariaRAT_O_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 70 20 00 01 00 00 14 14 14 6f 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}