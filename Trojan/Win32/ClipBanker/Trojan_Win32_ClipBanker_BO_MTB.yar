
rule Trojan_Win32_ClipBanker_BO_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 fc 50 e8 90 01 02 ff ff 83 c4 04 0f b6 c8 85 c9 74 90 01 01 68 90 01 02 40 00 e8 90 01 02 ff ff 83 c4 04 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}