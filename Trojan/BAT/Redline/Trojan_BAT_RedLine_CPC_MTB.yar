
rule Trojan_BAT_RedLine_CPC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.CPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 28 88 00 00 06 03 28 87 00 00 06 28 88 00 00 06 0a de } //05 00 
		$a_01_1 = {7e 02 00 00 04 7e 05 00 00 04 28 8a 00 00 06 17 8d 5c 00 00 01 25 16 1f 7c 9d 6f c2 00 00 0a 0d 16 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}