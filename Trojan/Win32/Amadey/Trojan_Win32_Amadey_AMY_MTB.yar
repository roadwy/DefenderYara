
rule Trojan_Win32_Amadey_AMY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 69 f6 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 33 f1 3b d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AMY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 2b c6 57 3b f8 77 ?? 8d 04 3e 83 fb 10 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 0f 43 85 ?? ?? ?? ?? 03 f0 8d 85 ?? ?? ?? ?? 50 56 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AMY_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 8b f9 ff 77 04 ff 15 70 b5 69 00 8b f0 56 ff 15 38 b5 69 00 89 45 d8 0f 57 c0 8d 45 ec } //2
		$a_01_1 = {54 45 4d 50 5c 70 69 78 65 6c 73 65 65 2d 69 6e 73 74 61 6c 6c 65 72 2d 74 6d 70 } //1 TEMP\pixelsee-installer-tmp
		$a_01_2 = {4d 65 64 69 61 47 65 74 5c 6d 65 64 69 61 67 65 74 2e 65 78 65 } //1 MediaGet\mediaget.exe
		$a_01_3 = {50 69 78 65 6c 53 65 65 20 4c 4c 43 } //1 PixelSee LLC
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_Win32_Amadey_AMY_MTB_4{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51 c7 84 24 18 02 00 00 84 82 10 45 c7 84 24 08 01 00 00 80 d9 0f 28 c7 84 24 20 01 00 00 5a 91 84 3c c7 84 24 ac 01 00 00 c2 99 3e 72 c7 84 24 e0 00 00 00 f4 09 87 1b c7 84 24 00 02 00 00 d9 b0 ba 48 c7 84 24 50 01 00 00 02 a6 fb 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}