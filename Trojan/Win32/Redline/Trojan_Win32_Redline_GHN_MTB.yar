
rule Trojan_Win32_Redline_GHN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 c7 45 ?? ?? ?? ?? ?? 8a 4c 0d ?? 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? 40 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GHN_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 83 e2 03 8a 8a ?? ?? ?? ?? 30 0c 38 40 3b c6 72 ?? 5f 5e c3 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}