
rule TrojanSpy_BAT_Noon_SV_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 14 11 04 5d 13 15 11 14 17 58 13 16 07 11 15 91 13 17 07 11 15 11 17 08 11 14 1f 16 5d 91 61 07 11 16 11 04 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 14 17 58 13 14 11 14 11 04 09 17 58 5a fe 04 13 18 11 18 2d b2 } //02 00 
		$a_01_1 = {50 72 6f 51 75 6f 74 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  ProQuota.Properties.Resources
	condition:
		any of ($a_*)
 
}