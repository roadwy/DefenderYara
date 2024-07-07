
rule Trojan_BAT_CyberGate_NE_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 17 9a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 7e 15 00 00 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 80 18 00 00 04 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}