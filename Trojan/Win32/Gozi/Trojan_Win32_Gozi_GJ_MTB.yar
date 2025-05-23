
rule Trojan_Win32_Gozi_GJ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 44 01 03 33 c9 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 45 ?? 69 c0 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 a2 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 4d ?? 8d 44 08 ?? 89 45 ?? ff 65 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {29 18 8b 3d ?? ?? ?? ?? 0f b6 ca 03 ce 8d 73 ?? 03 f1 8a cb c0 e1 ?? 2a cb c0 e1 ?? 2a ca 8a d1 88 15 ?? ?? ?? ?? 83 e8 04 3d ?? ?? ?? ?? 7f } //10
		$a_02_1 = {89 02 83 c2 04 a3 ?? ?? ?? ?? 8a c1 c0 e0 ?? 02 c1 89 54 24 ?? 8a 0d ?? ?? ?? ?? 02 c0 2a c8 83 6c 24 ?? 01 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}