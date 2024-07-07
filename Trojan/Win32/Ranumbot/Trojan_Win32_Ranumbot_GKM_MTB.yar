
rule Trojan_Win32_Ranumbot_GKM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 f8 94 08 00 01 85 90 01 04 8b 85 90 01 04 8a 04 08 8b 15 90 01 04 88 04 0a a1 90 01 04 3d 03 02 00 00 75 90 01 01 89 35 90 01 04 41 3b c8 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}