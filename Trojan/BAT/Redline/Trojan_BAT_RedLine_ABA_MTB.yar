
rule Trojan_BAT_RedLine_ABA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 20 00 01 00 00 8c 90 01 03 01 a2 25 1a 16 8d 90 01 03 01 a2 14 14 14 17 28 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}