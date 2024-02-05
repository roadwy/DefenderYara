
rule Trojan_Win32_Ranumbot_KM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3b cd 76 90 01 01 8b 35 90 01 04 8a 94 06 90 01 04 8b 3d 90 01 04 88 14 07 81 f9 03 02 00 00 75 90 01 01 89 2d 90 01 04 40 3b c1 72 90 01 01 8b 3d 90 01 04 33 f6 eb 90 01 01 8d 49 00 81 fe 6c 02 05 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}