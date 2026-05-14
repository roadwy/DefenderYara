
rule Trojan_Win64_Tedy_SXG_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 20 41 b9 10 00 00 00 4c 8d 45 ?? ba 04 61 40 9c 48 8b } //20
		$a_03_1 = {24 30 c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 c0 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b ?? 0f 57 c0 } //10
		$a_01_2 = {5c 5c 2e 5c 57 69 6e 4d 73 72 44 65 76 } //2 \\.\WinMsrDev
		$a_80_3 = {44 72 69 76 65 72 20 69 73 20 61 6c 72 65 61 64 79 20 6c 6f 61 64 65 64 } //Driver is already loaded  2
		$a_80_4 = {5c 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //\ntoskrnl.exe  2
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=36
 
}