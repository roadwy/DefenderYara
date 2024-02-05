
rule Trojan_Win32_Ursnif_AM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 89 44 24 90 01 01 6b c0 90 01 01 0f b7 f1 3b f0 74 90 01 01 6b 44 24 20 90 01 01 8b d6 2b d0 89 54 24 90 00 } //01 00 
		$a_02_1 = {69 c0 82 53 00 00 89 11 89 15 90 01 04 0f b7 c8 66 a3 90 01 04 8d 86 90 01 04 89 4c 24 90 01 01 8b f5 8d 14 41 8b cf 03 d0 8b 44 24 90 01 01 2b ca 89 54 24 90 01 01 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}