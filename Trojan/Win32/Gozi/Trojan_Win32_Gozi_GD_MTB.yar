
rule Trojan_Win32_Gozi_GD_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 8b 45 ?? 89 45 ?? ff 75 ?? 66 0f b6 05 ?? ?? ?? ?? ba ?? ?? ?? ?? 66 03 c2 0f b7 c8 0f b6 05 ?? ?? ?? ?? 03 c2 8a d0 02 d2 00 15 ?? ?? ?? ?? c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f8 89 bb ?? ?? ?? ?? 83 fb 00 76 [0-1e] fc f3 a4 52 c7 04 e4 ff ff 0f 00 ?? 8b 83 ?? ?? ?? ?? 52 81 04 e4 ?? ?? ?? ?? 29 14 e4 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 01 83 ?? ?? ?? ?? ff a3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 [0-30] 01 1d [0-20] 8b ff a1 [0-10] 8b 0d [0-20] 89 08 5f } //1
		$a_02_1 = {8b 4d fc 89 4d f4 8b 15 [0-20] 03 55 ?? 89 15 [0-20] 8b 45 ?? 89 45 ?? 8b 4d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ce 4f 81 c1 ?? ?? ?? ?? 8a 09 88 8e ?? ?? ?? ?? 46 85 d2 77 ?? 72 ?? 83 f8 1e 77 } //10
		$a_02_1 = {2b c2 2b c3 83 c0 ?? 0f b7 d8 8b 06 05 ?? ?? ?? ?? 89 06 83 c6 04 a3 ?? ?? ?? ?? 8b c3 2b 05 ?? ?? ?? ?? 83 e8 08 83 ed 01 75 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}