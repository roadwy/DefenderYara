
rule Trojan_Win64_CobaltStrike_DF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 03 90 01 01 48 ff c0 41 3a 4c 03 90 01 01 0f 85 90 01 04 48 83 f8 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {30 10 ff c1 48 8d 40 90 01 01 83 f9 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}