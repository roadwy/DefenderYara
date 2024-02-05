
rule Trojan_Win32_Redline_GHN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 c7 45 90 01 05 8a 4c 0d 90 01 01 32 88 90 01 04 88 88 90 01 04 c7 45 fc 90 01 04 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GHN_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d0 83 e2 03 8a 8a 90 01 04 30 0c 38 40 3b c6 72 90 01 01 5f 5e c3 90 00 } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}