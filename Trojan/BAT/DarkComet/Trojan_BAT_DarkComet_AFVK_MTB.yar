
rule Trojan_BAT_DarkComet_AFVK_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AFVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 18 07 08 02 08 91 06 20 00 01 00 00 6f ?? ?? ?? 0a d2 61 d2 9c 08 17 58 0c 08 02 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}