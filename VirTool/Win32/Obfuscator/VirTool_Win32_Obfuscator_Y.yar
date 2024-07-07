
rule VirTool_Win32_Obfuscator_Y{
	meta:
		description = "VirTool:Win32/Obfuscator.Y,SIGNATURE_TYPE_PEHSTR,64 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5d c3 00 00 ff ff ff 20 68 69 64 64 65 6e 20 6e 6f 77 21 00 00 00 00 ff ff ff ff 17 00 00 00 59 6f 75 20 63 61 6e 20 6e 65 76 65 72 20 63 61 74 63 68 20 6d 65 21 00 ff ff ff ff 06 00 00 00 4e 65 76 65 72 21 00 00 ff ff ff ff 13 00 00 00 59 6f 75 20 68 61 76 65 20 6e 6f 20 63 68 61 6e 63 65 21 } //1
		$a_01_2 = {ba ec 40 00 10 8b c6 e8 f2 fa ff ff 8b d8 b8 6c } //1
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
		$a_01_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_6 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_01_7 = {8b ec 83 c4 f0 53 56 b8 e8 3f 00 10 e8 7a f6 ff ff be 68 66 00 10 33 c0 55 68 db 40 00 10 64 ff 30 64 89 20 e8 fa f8 ff ff ba ec 40 00 10 8b c6 e8 f2 fa ff ff 8b d8 b8 6c 66 00 10 8b 16 e8 88 f2 ff ff b8 6c 66 00 10 e8 76 f2 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}