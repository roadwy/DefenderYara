
rule Trojan_BAT_RedLine_PTEW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.PTEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b d9 00 00 04 61 28 90 01 01 00 00 06 7e 48 01 00 04 28 90 01 01 05 00 06 7e 49 01 00 04 28 90 01 01 05 00 06 13 31 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}