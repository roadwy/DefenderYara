
rule Trojan_Win32_SmokeLoader_DH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {c1 e2 04 89 54 24 14 8b 44 24 24 01 44 24 14 8b c7 c1 e8 05 8d 34 2f c7 05 90 02 04 19 36 6b ff c7 05 90 02 04 ff ff ff ff 89 44 24 10 8b 44 24 20 01 44 24 10 8b 0d 90 02 04 81 f9 79 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}