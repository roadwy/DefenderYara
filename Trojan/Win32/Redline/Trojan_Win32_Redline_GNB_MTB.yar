
rule Trojan_Win32_Redline_GNB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff 80 34 3e 90 01 01 83 c4 28 46 3b 74 24 18 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNB_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 e6 66 c1 df fa 66 81 ca cc 00 66 f7 e1 33 d8 81 ee 90 01 04 8b fe 66 0b db c1 e7 5a 03 d9 0f bf d2 8b c7 66 f7 e0 66 03 f0 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNB_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c1 e2 02 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 f7 d0 88 45 90 01 01 0f b6 4d 90 01 01 81 c1 90 01 04 88 4d 90 01 01 0f b6 55 90 01 01 83 f2 90 01 01 88 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNB_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c8 83 e1 03 8a 89 90 01 04 30 88 90 01 04 40 3d 90 01 04 72 90 00 } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}