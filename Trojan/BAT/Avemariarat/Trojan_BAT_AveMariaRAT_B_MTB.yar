
rule Trojan_BAT_AveMariaRAT_B_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 1b 1a 9a 18 8d 90 01 01 00 00 01 25 16 11 05 a2 25 17 16 16 02 17 8d 90 01 01 00 00 01 25 16 11 05 a2 14 28 90 00 } //01 00 
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00 
		$a_01_2 = {73 65 74 5f 4b 65 65 70 41 6c 69 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}