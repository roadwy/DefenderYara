
rule Ransom_Win32_Genasom_CN{
	meta:
		description = "Ransom:Win32/Genasom.CN,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 06 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 8d 45 fc b9 ?? ?? ?? 00 e8 ?? ?? ?? ?? 6a ff 8b 45 fc e8 ?? ?? ?? ?? 50 8d 55 f4 33 c0 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ba 06 00 00 00 8b 45 fc e8 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 03 ba 01 00 00 80 } //5
		$a_00_1 = {5c 53 6f 75 6e 64 2e 65 78 65 } //5 \Sound.exe
		$a_00_2 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c } //5 System\CurrentControlSet\Control\SafeBoot\
		$a_00_3 = {5c 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 \taskmgr.exe
		$a_00_4 = {5c 64 65 6c 2e 62 61 74 } //1 \del.bat
		$a_00_5 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=17
 
}