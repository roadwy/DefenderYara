
rule Trojan_Win32_Zenpak_SB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 d7 01 f7 81 c7 ?? ?? ?? ?? 8b 37 69 f8 ?? ?? ?? ?? 89 d3 01 fb 8b 3b 69 d8 ?? ?? ?? ?? 01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b 75 c4 01 ce 89 34 24 89 7c 24 04 89 54 24 08 89 45 b4 89 4d b0 89 55 ac e8 ?? ?? ?? ?? 8b 45 ac 8b 4d b0 01 c8 8b 55 b4 81 c2 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 89 45 b8 89 55 bc 0f 84 } //10
		$a_01_1 = {56 30 45 53 57 59 56 70 33 67 44 72 58 67 65 31 54 43 73 65 56 2e 70 64 62 } //1 V0ESWYVp3gDrXge1TCseV.pdb
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}