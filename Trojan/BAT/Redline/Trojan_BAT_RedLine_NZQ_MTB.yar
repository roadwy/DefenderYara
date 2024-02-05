
rule Trojan_BAT_RedLine_NZQ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 91 07 08 07 8e 69 5d 91 61 28 dc 00 00 06 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 } //01 00 
		$a_01_1 = {66 00 00 13 66 00 73 00 64 00 66 00 66 00 64 00 66 00 20 00 66 00 00 0b 32 00 32 00 32 00 32 00 41 } //01 00 
		$a_81_2 = {66 64 73 66 66 66 66 64 66 66 73 64 66 } //01 00 
		$a_81_3 = {61 64 73 73 73 73 73 73 73 73 73 73 73 61 } //00 00 
	condition:
		any of ($a_*)
 
}