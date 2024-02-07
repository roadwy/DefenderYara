
rule Trojan_Win64_CobaltStrike_YAA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 55 ff 0f b6 45 fe 01 d0 88 45 f7 0f b6 45 fe 88 45 ff 0f b6 45 fd 88 45 fe 0f b6 45 fd 00 45 f7 } //01 00 
		$a_01_1 = {0f b6 00 8b 55 f8 48 63 ca 48 8b 55 18 48 01 ca 32 45 f7 88 02 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}