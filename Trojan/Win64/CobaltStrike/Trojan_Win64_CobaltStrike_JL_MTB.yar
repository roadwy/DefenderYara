
rule Trojan_Win64_CobaltStrike_JL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 f2 1f 41 fe c0 88 14 01 41 0f b6 c8 42 8a 54 09 01 84 d2 } //01 00 
		$a_01_1 = {41 8b 41 24 49 03 c0 8b ca 0f b7 14 48 41 8b 49 1c 49 03 c8 8b 34 91 49 03 f0 } //00 00 
	condition:
		any of ($a_*)
 
}