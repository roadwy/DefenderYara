
rule Trojan_Win32_CobaltStrike_BMM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {88 06 46 8b d2 43 8b d2 83 c1 02 4f 8b d7 85 fa 75 90 0a 30 00 66 2b 05 90 01 04 66 f7 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}