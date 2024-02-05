
rule Trojan_Win32_Farfli_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 10 8b 40 10 33 ff 03 c2 33 d2 8b c8 2b ce 3b f0 0f 47 ca 89 4d 0c 85 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c9 76 11 8d 44 24 0c 50 52 51 8b 4f e4 51 ff 15 90 01 04 8b 13 0f b7 42 06 45 83 c7 28 3b e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 28 4b c6 44 24 2a 52 c6 44 24 2b 4e c6 44 24 2d 4c c6 44 24 2e 33 c6 44 24 2f 32 c6 44 24 30 2e c6 44 24 31 64 88 44 24 32 88 44 24 33 c6 44 24 34 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 02 d0 32 d0 02 d0 32 d0 88 11 } //00 00 
	condition:
		any of ($a_*)
 
}