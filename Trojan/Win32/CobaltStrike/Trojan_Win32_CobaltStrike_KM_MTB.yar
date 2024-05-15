
rule Trojan_Win32_CobaltStrike_KM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8d 55 90 01 01 8b 45 90 01 01 01 d0 0f b6 00 31 c1 89 ca 8d 8d 90 01 04 8b 45 90 01 01 01 c8 88 10 83 45 90 01 02 83 45 90 01 02 8b 45 90 01 01 3d 90 01 04 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}