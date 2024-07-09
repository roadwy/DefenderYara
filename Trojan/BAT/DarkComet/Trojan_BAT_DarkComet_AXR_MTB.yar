
rule Trojan_BAT_DarkComet_AXR_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 31 00 00 01 0c 03 8e b7 17 da 0a 2b 19 08 06 17 da 02 03 06 91 03 06 17 da 91 65 b5 6f ?? ?? ?? 06 9c 06 15 d6 0a 06 17 2f e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}