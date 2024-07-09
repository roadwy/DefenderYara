
rule VirTool_Win32_CeeInject_GL{
	meta:
		description = "VirTool:Win32/CeeInject.GL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 00 00 99 b9 ?? ?? 00 00 f7 f9 33 d2 8a 90 90 ?? ?? ?? 00 8b ca 83 f1 ?? 33 d2 8a 15 ?? ?? ?? 00 33 ca 83 f1 90 09 06 00 8b 45 ?? 69 } //1
		$a_03_1 = {00 df e0 f6 c4 41 75 ?? 68 00 dc ab 40 6a 00 90 90 90 90 e9 90 09 08 00 db 45 ?? dc 1d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_GL_2{
	meta:
		description = "VirTool:Win32/CeeInject.GL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 69 c0 15 1a 00 00 99 b9 15 1a 00 00 f7 f9 0f b6 0c 85 ?? ?? ?? 00 0f b6 05 ?? ?? ?? 00 33 c8 8b 45 fc 69 c0 15 1a 00 00 99 be 15 1a 00 00 f7 fe e9 } //1
		$a_03_1 = {69 c0 c5 11 00 00 99 b9 c5 11 00 00 f7 f9 d9 04 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a d8 81 e3 ff ?? 00 00 d9 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 25 ff ?? 00 00 33 d8 8b 45 f0 69 c0 c5 11 00 00 } //1
		$a_03_2 = {b8 ff a3 a4 52 f7 e9 c1 fa 0b 8b ca c1 e9 1f 03 d1 d9 04 95 ?? ?? ?? ?? e8 ?? ?? ?? ?? d9 05 ?? ?? ?? ?? 8a d8 e8 ?? ?? ?? ?? 32 d8 b8 4b 94 aa 3b } //1
		$a_03_3 = {b8 5d 1c 68 0e 8d b4 15 50 e2 ff ff f7 ef 90 09 12 00 b8 ?? be a0 2f f7 6d f8 c1 fa 03 8b c2 c1 e8 1f 03 d0 } //1
		$a_03_4 = {b8 e5 dc 55 51 f7 6d ?? c1 fa 0a 8b ca c1 e9 1f 03 d1 8b fa dd 04 fd ?? ?? ?? ?? e8 ?? ?? ?? ?? dd 05 ?? ?? ?? ?? 8a d8 e8 ?? ?? ?? ?? 32 d8 88 9c 3d ?? ?? ?? ?? 90 90 } //1
		$a_00_5 = {b8 3b 72 95 73 f7 6d d8 c1 fa 08 8b c2 c1 e8 1f 03 d0 02 84 15 30 eb ff ff 3c 05 8d 8c 15 30 eb ff ff 77 22 90 90 90 90 90 b8 83 be a0 2f } //1
		$a_03_6 = {68 00 1f c1 40 6a 00 8d 54 24 48 ff d2 83 c4 08 b8 bb 57 9e 77 f7 ef c1 fa 0c 8b c2 c1 e8 1f 03 d0 dd 04 d5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a c8 b8 67 66 66 66 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1) >=1
 
}