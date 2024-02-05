
rule Trojan_BAT_RedLine_MP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 28 c3 00 00 06 03 28 c2 00 00 06 28 c3 00 00 06 0a de 05 } //00 00 
	condition:
		any of ($a_*)
 
}