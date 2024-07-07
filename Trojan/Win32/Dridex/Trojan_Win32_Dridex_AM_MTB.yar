
rule Trojan_Win32_Dridex_AM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 6f 88 c1 80 c1 9d 88 4c 24 4f 88 c1 80 f1 e3 88 4c 24 55 } //10
		$a_01_1 = {88 44 24 33 89 d0 89 54 24 2c f7 e7 69 fe 6e c6 03 7a 01 fa 89 44 24 60 89 54 24 64 0f b6 c1 83 f8 6a } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {74 6f 6b 65 6e 79 74 68 65 73 50 65 70 70 65 72 } //tokenythesPepper  3
		$a_80_1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 76 4e 76 73 74 65 76 65 72 65 74 75 72 6e 2e 74 68 65 45 } //application.vNvstevereturn.theE  3
		$a_80_2 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  3
		$a_80_3 = {67 70 6f 69 72 65 65 } //gpoiree  3
		$a_80_4 = {53 48 47 65 74 44 65 73 6b 74 6f 70 46 6f 6c 64 65 72 } //SHGetDesktopFolder  3
		$a_80_5 = {44 44 70 6c 73 6f 65 63 72 56 77 71 61 73 65 } //DDplsoecrVwqase  3
		$a_80_6 = {52 65 67 4c 6f 61 64 41 70 70 4b 65 79 41 } //RegLoadAppKeyA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AM_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 65 73 69 67 6e 38 73 65 72 76 65 72 2e 31 31 34 4f 4f 63 74 6f 62 65 72 50 4e 62 } //Design8server.114OOctoberPNb  3
		$a_80_1 = {62 6f 73 74 6f 6e 6b 65 70 74 50 76 65 72 73 69 6f 6e 73 3b 54 68 65 50 50 41 50 49 6e 4a 32 } //bostonkeptPversions;ThePPAPInJ2  3
		$a_80_2 = {4c 6f 73 73 6b 69 77 46 70 70 6f 6e 66 } //LosskiwFpponf  3
		$a_80_3 = {66 66 67 74 62 79 77 71 2e 70 64 62 } //ffgtbywq.pdb  3
		$a_80_4 = {43 72 79 70 74 53 49 50 43 72 65 61 74 65 49 6e 64 69 72 65 63 74 44 61 74 61 } //CryptSIPCreateIndirectData  3
		$a_80_5 = {52 61 73 44 65 6c 65 74 65 45 6e 74 72 79 57 } //RasDeleteEntryW  3
		$a_80_6 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 44 24 14 04 8d 0c 40 2b 4c 24 18 ff 4c 24 24 0f b7 d1 8a 4c 24 0c } //10
		$a_01_1 = {8b c8 2b ce 2b cb 8b f1 0f b7 ca 03 cf } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AM_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 20 01 c1 88 cb 88 5c 24 5f 8a 5c 24 5f 8b 84 24 f0 00 00 00 8b 4d 08 88 1c 01 } //10
		$a_01_1 = {8b 45 10 8b 8c 24 04 01 00 00 8a 94 24 0f 01 00 00 32 94 24 0f 01 00 00 88 94 24 0f 01 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AM_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.AM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c1 89 45 f4 8b 55 fc 8b 45 f0 8a 08 88 0a 8b 55 fc } //10
		$a_01_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 10 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}