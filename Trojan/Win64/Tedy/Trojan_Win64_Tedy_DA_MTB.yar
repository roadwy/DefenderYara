
rule Trojan_Win64_Tedy_DA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 48 8d 0d ?? ?? ?? ?? 48 8b 54 24 08 0f b6 0c 11 2b c1 05 00 01 00 00 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 48 8b 0c 24 48 8b 54 24 28 48 03 d1 48 8b ca 88 01 48 8b 44 24 08 48 ff c0 33 d2 b9 08 00 00 00 48 f7 f1 48 8b c2 48 89 44 24 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_DA_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 5c 2e 5c 56 42 6f 78 4d 69 6e 69 52 64 72 44 4e } //10 \\.\VBoxMiniRdrDN
		$a_81_1 = {46 6f 72 74 6e 69 74 65 43 6c 69 65 6e 74 2d 57 69 6e 36 34 2d 53 68 69 70 70 69 6e 67 2e 65 78 65 } //10 FortniteClient-Win64-Shipping.exe
		$a_81_2 = {44 33 44 31 31 43 72 65 61 74 65 44 65 76 69 63 65 41 6e 64 53 77 61 70 43 68 61 69 6e } //1 D3D11CreateDeviceAndSwapChain
		$a_81_3 = {64 33 64 31 31 2e 64 6c 6c } //1 d3d11.dll
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=22
 
}