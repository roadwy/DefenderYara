
rule Trojan_BAT_DarkComet_AKD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 0b 2b 24 02 07 02 07 91 02 07 17 d6 02 8e b7 5d 91 d6 20 00 01 00 00 5d b4 03 07 03 8e b7 5d 91 61 9c 00 07 17 d6 0b 07 08 0d 09 31 d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}