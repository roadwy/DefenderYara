
rule Trojan_BAT_DarkComet_AEU_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 08 02 8e b7 5d 02 08 02 8e b7 5d 91 07 08 07 8e b7 5d 91 61 02 08 17 58 02 8e b7 5d 91 59 } //00 00 
	condition:
		any of ($a_*)
 
}