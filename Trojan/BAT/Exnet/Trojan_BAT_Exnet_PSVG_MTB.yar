
rule Trojan_BAT_Exnet_PSVG_MTB{
	meta:
		description = "Trojan:BAT/Exnet.PSVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 8e 69 18 da 0b 73 ?? 00 00 0a 0c 07 0d 16 13 04 2b 1a 08 02 11 04 9a 28 ?? 00 00 0a 1f 59 da b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}