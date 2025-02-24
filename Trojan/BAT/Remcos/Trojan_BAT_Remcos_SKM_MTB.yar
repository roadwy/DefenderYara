
rule Trojan_BAT_Remcos_SKM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 02 03 06 04 28 42 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0b 07 2d d7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}