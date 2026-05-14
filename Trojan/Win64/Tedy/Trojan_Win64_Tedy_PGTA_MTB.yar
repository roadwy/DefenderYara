
rule Trojan_Win64_Tedy_PGTA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 "
		
	strings :
		$a_01_0 = {33 ca 45 33 c1 42 89 4c 9b 14 49 8d 53 06 41 8b c0 24 01 f6 d8 1b c9 81 e1 df b0 08 99 42 33 8c 9b 8c fc ff ff 4c 8b da 41 d1 e8 41 33 c8 89 0c 93 48 81 fa e0 04 00 00 0f 82 } //5
		$a_80_1 = {4e 45 58 2d 53 48 41 44 4f 57 2d 50 52 4f 54 00 4d 55 54 41 54 45 44 2d 49 44 45 4e 54 49 54 59 } //NEX-SHADOW-PROT  10
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 74 69 6d 65 6f 75 74 20 2f 74 20 31 20 26 26 20 64 65 6c 20 2f 66 20 2f 71 20 22 } //cmd.exe /c "timeout /t 1 && del /f /q "  4
		$a_80_3 = {68 74 74 70 64 65 62 75 67 67 65 72 75 69 2e 65 78 65 } //httpdebuggerui.exe  2
		$a_80_4 = {77 69 72 65 73 68 61 72 6b 2e 65 78 65 } //wireshark.exe  2
		$a_80_5 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //ollydbg.exe  3
		$a_80_6 = {69 64 61 2e 65 78 65 } //ida.exe  3
		$a_80_7 = {78 36 34 64 62 67 2e 65 78 65 } //x64dbg.exe  3
		$a_80_8 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //procmon.exe  1
		$a_80_9 = {66 69 64 64 6c 65 72 2e 65 78 65 } //fiddler.exe  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*10+(#a_80_2  & 1)*4+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=25
 
}