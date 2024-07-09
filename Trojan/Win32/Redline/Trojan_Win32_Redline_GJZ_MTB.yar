
rule Trojan_Win32_Redline_GJZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 47 e2 } //10
		$a_03_1 = {f7 d2 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? f7 d8 88 85 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_GJZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}