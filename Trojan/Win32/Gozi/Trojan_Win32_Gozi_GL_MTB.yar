
rule Trojan_Win32_Gozi_GL_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b c1 03 05 90 01 04 a3 90 01 04 0f b6 05 90 01 04 6b c0 90 01 01 8b 0d 90 01 04 2b c8 a1 90 01 04 2b c1 a3 90 01 04 0f b7 45 90 01 01 8b 4d 90 01 01 8d 44 08 90 01 01 66 89 45 90 01 01 a1 90 01 04 8b 0d 90 01 04 8d 44 01 90 01 01 a2 90 01 04 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {f6 eb 8a d9 2a d8 0f b7 c1 69 c0 90 01 04 2b 05 90 01 04 a3 90 01 04 0f b6 c3 81 c6 90 01 04 66 8b c8 89 37 66 c1 e0 90 01 01 83 c7 04 66 03 c8 89 35 90 01 04 66 03 4c 24 90 01 01 8d 42 90 01 01 8b 74 24 90 01 01 0f b7 c9 02 c1 02 d8 ff 4c 24 90 01 01 66 8b 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}