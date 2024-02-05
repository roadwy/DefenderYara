
rule Trojan_Win32_CobaltStrike_A_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b d2 0a 0f b6 08 83 e9 30 40 03 d1 80 38 00 75 } //01 00 
		$a_03_1 = {33 d2 0f b7 01 33 d2 66 2b 05 90 02 04 66 f7 35 90 02 04 88 06 46 33 d2 43 33 d2 83 c1 02 4f 85 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}