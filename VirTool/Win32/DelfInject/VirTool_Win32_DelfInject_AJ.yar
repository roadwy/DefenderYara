
rule VirTool_Win32_DelfInject_AJ{
	meta:
		description = "VirTool:Win32/DelfInject.AJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //1 Portions Copyright (c) 1999,2003 Avenger by NhT
		$a_00_1 = {6e 65 77 63 72 79 70 74 } //1 newcrypt
		$a_00_2 = {57 6f 72 6d 55 6e 68 6f 6f 6b } //1 WormUnhook
		$a_00_3 = {5c 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 \ntoskrnl.exe
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_02_5 = {89 45 fc 68 03 01 00 00 8b 45 fc 50 e8 90 01 02 ff ff 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 90 90 ef ff ff 8b 55 fc e8 90 01 02 ff ff 8d 85 90 90 ef ff ff ba 90 01 02 00 10 e8 90 01 02 ff ff 8b 85 90 90 ef ff ff e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 8b d8 6a 00 6a 00 6a 00 53 e8 90 01 02 ff ff 6a 00 53 e8 90 01 02 ff ff 8b f0 8b c6 e8 90 01 02 ff ff 89 45 f4 6a 00 8d 45 f0 50 56 8b 7d f4 57 53 90 00 } //1
		$a_00_6 = {8b d8 4b 85 db 7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 } //1
		$a_02_7 = {8b 37 03 75 f8 68 90 01 02 00 10 56 e8 90 01 02 ff ff 85 c0 75 1b 8b 45 e8 8b 40 1c 8b 55 e0 0f b7 12 c1 e2 02 03 c2 03 45 f8 8b 00 89 45 d0 eb 0a 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}