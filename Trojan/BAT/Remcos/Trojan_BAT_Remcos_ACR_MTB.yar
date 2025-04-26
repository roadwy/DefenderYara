
rule Trojan_BAT_Remcos_ACR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 6f 23 00 00 0a 16 2d bc 06 6f 24 00 00 0a 16 6a 31 44 2b 0a 0d 2b c5 13 04 2b cf 0a 2b d5 06 6f 1f 00 00 0a 0c 06 6f 25 00 00 0a 07 08 16 08 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}