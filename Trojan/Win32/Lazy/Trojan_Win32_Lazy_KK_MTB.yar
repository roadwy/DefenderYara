
rule Trojan_Win32_Lazy_KK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e } //20
		$a_01_1 = {44 6b 63 73 6b 2e 65 78 65 } //10 Dkcsk.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Lazy_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c b1 b5 01 db dd 33 c6 6e 32 97 4c 65 3e 9c } //20
		$a_01_1 = {ac 32 c4 fe c4 c0 c4 02 80 c4 90 aa e2 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Lazy_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 0f b6 c4 c1 e0 08 09 d0 0f b6 d7 c1 e2 10 09 c2 0f b6 c3 c1 e0 18 09 d0 66 0f 6e c8 66 0f ef c8 66 ?? ?? ?? ?? 46 83 fe 3c } //20
		$a_01_1 = {8a 1c 82 88 1c 81 8a 5c 82 01 88 5c 81 01 8a 5c 82 02 88 5c 81 02 8a 5c 82 03 88 5c 81 03 40 83 f8 08 75 dc } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win32_Lazy_KK_MTB_4{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 57 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 a0 74 ?? 00 68 d8 73 ?? 00 6a 00 ff } //20
		$a_03_1 = {8b 4d bc 8b 14 8d 28 71 ?? 00 03 55 b4 8a 0c 03 03 d3 43 88 4c 32 2e 3b df } //10
		$a_01_2 = {46 61 6b 65 43 68 72 6f 6d 65 5c 52 65 6c 65 61 73 65 5c 43 68 72 6f 6d 65 2e 70 64 62 } //5 FakeChrome\Release\Chrome.pdb
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}