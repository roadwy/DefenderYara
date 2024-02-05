
rule Trojan_BAT_Startun_SPH_MTB{
	meta:
		description = "Trojan:BAT/Startun.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 17 8d 50 00 00 01 25 16 1f 3d 9d 6f 90 01 03 0a 13 06 11 06 17 9a 6f 90 01 03 0a 28 90 01 03 0a 13 04 11 06 16 9a 6f 90 01 03 0a 72 e9 02 00 70 28 90 01 03 0a 13 07 11 07 2c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}