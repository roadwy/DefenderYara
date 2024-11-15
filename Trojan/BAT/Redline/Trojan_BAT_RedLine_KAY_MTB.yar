
rule Trojan_BAT_RedLine_KAY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 34 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 35 91 61 d2 81 ?? 00 00 01 de 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}