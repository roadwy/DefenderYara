
rule Trojan_BAT_Remcos_EJN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 c8 00 00 00 59 1f 64 59 1f 1e 58 20 90 01 03 00 59 13 04 11 04 28 90 01 03 0a 28 90 01 03 0a 13 05 06 11 05 28 90 01 03 0a 28 90 01 03 0a 0a 07 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}