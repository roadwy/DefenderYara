
rule Trojan_Win32_Midie_SIB_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,39 00 38 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //50 Control_RunDLL
		$a_03_1 = {8b 11 31 f6 8d bc 24 ?? ?? ?? ?? bd ?? ?? ?? ?? 89 d3 [0-0a] 89 d1 c1 eb 04 b8 ?? ?? ?? ?? 80 e1 ?? 80 f9 ?? 0f 42 c5 46 00 c8 83 fa ?? 89 da 88 47 ff 8d 7f ff 77 } //1
		$a_03_2 = {8b 11 31 ed 8d bc 24 ?? ?? ?? ?? be ?? ?? ?? ?? 89 d3 [0-10] 89 d1 c1 eb 04 b8 ?? ?? ?? ?? 80 e1 ?? 80 f9 ?? 0f 42 c6 45 00 c8 83 fa ?? 89 da 88 47 ff 8d 7f ff 77 } //1
		$a_03_3 = {64 a1 30 00 00 00 89 7c 24 ?? 8b 40 0c 8b 68 14 89 6c 24 ?? 85 ed 0f 84 ?? ?? ?? ?? 66 90 90 8b 75 28 33 c9 0f b7 55 24 [0-0a] 0f b6 3e c1 c9 ?? 80 3e 61 72 03 83 c1 ?? 81 c2 ff ff 00 00 03 cf 46 66 85 d2 75 ?? 81 f9 ?? ?? ?? ?? 0f 85 } //5
	condition:
		((#a_00_0  & 1)*50+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*5) >=56
 
}