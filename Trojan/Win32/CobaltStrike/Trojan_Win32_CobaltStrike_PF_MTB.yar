
rule Trojan_Win32_CobaltStrike_PF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 33 d2 66 2b 05 90 01 04 66 f7 35 90 01 04 88 06 46 8b d2 43 8b d2 83 c1 90 01 01 4f 8b d7 85 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}