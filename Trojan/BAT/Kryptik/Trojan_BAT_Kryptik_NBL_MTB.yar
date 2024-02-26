
rule Trojan_BAT_Kryptik_NBL_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.NBL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 06 11 04 11 07 11 07 08 91 11 07 09 91 58 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 20 14 00 00 00 38 e1 fe ff ff } //01 00 
		$a_01_1 = {fe 0c 05 00 fe 0c 05 00 5a 6e fe 0c 1d 00 5e 6d fe 0e 05 00 fe 0c 0d 00 fe 0c 0d 00 18 62 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 34 00 58 fe 0e 0d 00 fe 0c 0d 00 fe 0c 0d 00 1d 64 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 27 00 58 fe 0e 0d 00 fe 0c 0d 00 fe 0c 0d 00 1f 09 62 61 fe 0e 0d 00 fe 0c 0d 00 fe 0c 05 00 58 fe 0e 0d 00 fe 0c 2f 00 1f 12 62 fe 0c 2f 00 58 fe 0c 34 00 61 fe 0c 0d 00 58 fe 0e 0d 00 fe 0c 0d 00 76 6c 6d 58 13 11 20 15 01 00 00 38 12 d4 ff ff } //00 00 
	condition:
		any of ($a_*)
 
}