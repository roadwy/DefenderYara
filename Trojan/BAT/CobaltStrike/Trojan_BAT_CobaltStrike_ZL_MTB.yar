
rule Trojan_BAT_CobaltStrike_ZL_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 8f 0f 00 00 01 25 71 90 01 03 01 20 90 01 03 00 61 d2 81 90 01 03 01 00 08 17 58 0c 08 07 8e 69 fe 04 13 06 11 06 2d d5 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //01 00  VirtualAllocEx
		$a_01_2 = {44 72 61 77 53 74 61 74 65 41 } //00 00  DrawStateA
	condition:
		any of ($a_*)
 
}