
rule Trojan_Win32_Ursnif_AAH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {05 64 65 b2 01 89 44 24 1c 83 eb 1f a3 90 01 04 89 06 8b 44 24 10 0f b7 c0 3d 5f b9 0c 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}