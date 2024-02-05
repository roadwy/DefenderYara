
rule Trojan_BAT_Diztakun_AZ_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 9a 0d 09 75 23 00 00 01 13 04 11 04 2d 36 09 75 39 00 00 01 2c 0a 09 a5 39 00 00 01 13 05 2b 58 09 75 3d 00 00 01 2c 0a 09 a5 3d 00 00 01 13 06 2b 57 09 75 3e 00 00 01 2c 75 09 a5 3e 00 00 01 13 07 2b 5c 06 11 04 06 } //00 00 
	condition:
		any of ($a_*)
 
}