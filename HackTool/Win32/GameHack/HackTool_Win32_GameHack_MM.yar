
rule HackTool_Win32_GameHack_MM{
	meta:
		description = "HackTool:Win32/GameHack.MM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 6f 69 6e 74 42 6c 61 6e 6b 2e 65 78 65 } //PointBlank.exe  1
		$a_80_1 = {7a 65 70 65 74 74 6f 2e 6f 6e 6c 69 6e 65 } //zepetto.online  1
		$a_80_2 = {47 61 67 61 6c 20 44 6f 77 6e 6c 6f 61 64 20 43 68 65 61 74 } //Gagal Download Cheat  1
		$a_80_3 = {76 69 70 65 6e 6a 6f 79 65 72 73 2e 78 79 7a } //vipenjoyers.xyz  1
		$a_80_4 = {76 76 69 70 65 67 6e 2e 63 6f 6d } //vvipegn.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}