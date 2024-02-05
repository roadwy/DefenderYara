
rule Trojan_BAT_DarkComet_AC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0b 16 02 8e b7 17 da 0d 0c 2b 12 02 08 02 08 91 07 08 07 8e b7 5d 91 61 9c 08 17 d6 0c 08 09 31 ea } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}