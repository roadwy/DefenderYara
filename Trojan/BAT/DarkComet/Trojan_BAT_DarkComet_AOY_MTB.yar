
rule Trojan_BAT_DarkComet_AOY_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AOY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 c4 09 00 00 28 90 01 03 0a 14 0b 17 72 90 01 03 70 12 00 73 90 01 03 0a 0b 06 2d 05 28 90 00 } //01 00 
		$a_01_1 = {52 65 6c 65 61 73 65 4d 75 74 65 78 } //00 00  ReleaseMutex
	condition:
		any of ($a_*)
 
}