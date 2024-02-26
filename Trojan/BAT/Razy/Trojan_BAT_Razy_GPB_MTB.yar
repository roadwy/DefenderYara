
rule Trojan_BAT_Razy_GPB_MTB{
	meta:
		description = "Trojan:BAT/Razy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {91 04 61 d2 9c 11 06 17 58 13 } //05 00 
		$a_01_1 = {00 53 74 72 52 65 76 65 72 73 65 00 } //00 00  匀牴敒敶獲e
	condition:
		any of ($a_*)
 
}