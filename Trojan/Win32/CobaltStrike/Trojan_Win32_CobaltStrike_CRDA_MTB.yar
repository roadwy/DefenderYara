
rule Trojan_Win32_CobaltStrike_CRDA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CRDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f ef c1 0f 11 84 05 90 01 04 0f 10 84 05 90 01 04 66 0f ef c1 0f 11 84 05 90 01 04 0f 10 84 05 90 01 04 66 0f ef c1 0f 11 84 05 90 01 04 0f 10 84 05 90 01 04 66 0f ef c1 0f 11 84 05 90 01 04 83 c0 40 3d c0 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}