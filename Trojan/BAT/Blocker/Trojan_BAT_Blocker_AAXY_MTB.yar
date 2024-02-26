
rule Trojan_BAT_Blocker_AAXY_MTB{
	meta:
		description = "Trojan:BAT/Blocker.AAXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 0a 00 73 90 01 01 00 00 0a 20 02 7e e1 e8 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 0a 06 16 06 8e 69 28 90 01 01 00 00 0a 06 0b de 03 26 de d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}