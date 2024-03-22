
rule Trojan_BAT_RedLine_PTIY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.PTIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 e1 01 00 0a 25 02 16 02 8e 69 6f b1 02 00 0a 6f b3 02 00 0a 06 28 90 01 01 03 00 06 28 90 01 01 03 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}