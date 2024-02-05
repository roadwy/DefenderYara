
rule Trojan_Win32_ClipBanker_BH_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {57 33 ff 57 ff 15 90 01 02 43 00 85 c0 74 90 01 01 56 6a 01 ff 15 90 01 02 43 00 8b f0 85 f6 74 90 01 01 56 ff 15 90 01 02 43 00 8b f8 57 ff 15 90 01 02 44 00 50 57 e8 7c 90 01 01 00 00 83 c4 0c 8b f8 56 ff 15 90 01 02 43 00 ff 15 90 01 02 43 00 8b c7 5e 5f c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}