
rule Trojan_BAT_zgRAT_Z_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 07 16 6f ?? 00 00 0a 0c 12 ?? 28 ?? 00 00 0a 0d 06 07 09 9c 07 17 58 0b 07 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}