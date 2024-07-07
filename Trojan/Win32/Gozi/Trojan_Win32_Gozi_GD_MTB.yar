
rule Trojan_Win32_Gozi_GD_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 8b 45 90 01 01 89 45 90 01 01 ff 75 90 01 01 66 0f b6 05 90 01 04 ba 90 01 04 66 03 c2 0f b7 c8 0f b6 05 90 01 04 03 c2 8a d0 02 d2 00 15 90 01 04 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f8 89 bb 90 01 04 83 fb 00 76 90 02 1e fc f3 a4 52 c7 04 e4 ff ff 0f 00 90 01 01 8b 83 90 01 04 52 81 04 e4 90 01 04 29 14 e4 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 ff a3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 90 02 30 01 1d 90 02 20 8b ff a1 90 02 10 8b 0d 90 02 20 89 08 5f 90 00 } //1
		$a_02_1 = {8b 4d fc 89 4d f4 8b 15 90 02 20 03 55 90 01 01 89 15 90 02 20 8b 45 90 01 01 89 45 90 01 01 8b 4d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Gozi_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ce 4f 81 c1 90 01 04 8a 09 88 8e 90 01 04 46 85 d2 77 90 01 01 72 90 01 01 83 f8 1e 77 90 00 } //10
		$a_02_1 = {2b c2 2b c3 83 c0 90 01 01 0f b7 d8 8b 06 05 90 01 04 89 06 83 c6 04 a3 90 01 04 8b c3 2b 05 90 01 04 83 e8 08 83 ed 01 75 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}