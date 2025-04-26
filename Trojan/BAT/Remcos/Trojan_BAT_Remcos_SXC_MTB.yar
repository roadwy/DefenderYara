
rule Trojan_BAT_Remcos_SXC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 16 2b 1e 11 16 6f ?? ?? ?? 0a 13 3c 11 11 11 3c 11 1f 59 61 13 11 11 1f 19 11 11 58 1e 63 59 13 1f 11 16 6f 3d 00 00 06 2d d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}