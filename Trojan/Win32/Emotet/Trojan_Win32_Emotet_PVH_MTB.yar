
rule Trojan_Win32_Emotet_PVH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 07 03 c1 99 b9 90 01 04 f7 f9 8b 44 24 54 83 c4 38 8a 4c 14 24 30 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}