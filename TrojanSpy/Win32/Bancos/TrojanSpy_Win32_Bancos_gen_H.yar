
rule TrojanSpy_Win32_Bancos_gen_H{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_02_0 = {8b f0 85 f6 7e 6b bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 74 40 8d 45 f0 50 b9 01 00 00 00 8b d3 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 74 1e 8d 45 ec 50 b9 01 00 00 00 } //10
		$a_00_1 = {00 73 65 6e 68 61 } //1 猀湥慨
		$a_00_2 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_00_3 = {69 6e 6e 65 72 68 74 6d 6c } //1 innerhtml
		$a_00_4 = {66 69 72 65 66 6f 78 } //1 firefox
		$a_00_5 = {2e 70 68 70 } //1 .php
		$a_01_6 = {49 6e 64 79 20 4c 69 62 72 61 72 79 } //1 Indy Library
		$a_01_7 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 } //1 Content-Type
		$a_01_8 = {43 50 6c 41 70 70 6c 65 74 } //1 CPlApplet
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}