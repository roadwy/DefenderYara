
rule Trojan_Win32_Emotet_BA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 25 ff 00 00 80 79 90 01 01 48 0d 00 ff ff ff 40 89 45 90 01 01 8b 45 90 01 01 0f b6 88 90 01 04 8b 55 90 01 01 0f b6 84 15 90 01 04 33 c8 8b 55 90 01 01 88 8a 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b c7 33 f6 89 74 24 14 8d 2c 08 8b 0d 90 01 04 8b f9 8b dd 0f af f9 0f af da 0f af fa 90 00 } //10
		$a_01_1 = {45 72 4a 49 5a 77 51 25 42 34 58 5f 23 2a 54 55 75 55 33 32 76 78 28 63 39 5f 40 38 2a 43 21 42 69 37 64 58 37 6f } //3 ErJIZwQ%B4X_#*TUuU32vx(c9_@8*C!Bi7dX7o
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}
rule Trojan_Win32_Emotet_BA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c6 99 be 90 01 04 f7 fe 8a 44 8c 04 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 04 89 44 b4 10 33 d2 8d 47 ff f7 f3 0f 90 00 } //1
		$a_00_1 = {8a 44 8c 10 8b f2 8b 54 b4 10 89 54 8c 10 0f b6 d0 89 54 b4 10 8b 44 8c 10 03 c2 99 f7 } //1
		$a_00_2 = {f7 fe 8a 44 8c 08 0f b6 c0 8b f2 8b 54 b4 10 89 54 8c 08 89 44 b4 10 33 d2 8b c7 f7 f3 0f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_BA_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {32 5a 54 59 58 47 37 4b 35 23 52 59 2b 28 75 52 52 61 45 26 4c 58 49 76 46 21 2b 40 3e 6d 37 37 39 73 45 6a 42 55 29 64 28 4d 62 33 5f 21 5a } //3 2ZTYXG7K5#RY+(uRRaE&LXIvF!+@>m779sEjBU)d(Mb3_!Z
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_81_2 = {50 61 74 68 46 69 6e 64 45 78 74 65 6e 73 69 6f 6e 57 } //3 PathFindExtensionW
		$a_81_3 = {50 61 74 68 46 69 6e 64 46 69 6c 65 4e 61 6d 65 57 } //3 PathFindFileNameW
		$a_81_4 = {50 61 74 68 53 74 72 69 70 54 6f 52 6f 6f 74 57 } //3 PathStripToRootW
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}