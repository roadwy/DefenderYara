
rule PWS_Win32_Frethog_B{
	meta:
		description = "PWS:Win32/Frethog.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 09 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 55 4e } //3 Windows\CurrentVersion\RUN
		$a_00_1 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 47 } //4 AVP.AlertDialoG
		$a_01_2 = {c8 f0 d0 c7 d7 a2 b2 e1 b1 ed bc e0 bf d8 cc e1 } //4
		$a_00_3 = {25 73 20 25 63 25 73 25 63 25 64 } //3 %s %c%s%c%d
		$a_00_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //3 explorer.exe
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //3 WriteProcessMemory
		$a_00_6 = {57 57 68 01 02 00 00 53 ff d6 57 57 68 02 02 00 00 53 ff d6 } //2
		$a_02_7 = {68 01 02 00 00 ?? ff d6 ?? ?? 68 02 02 00 00 ff 75 fc ff d6 68 } //2
		$a_00_8 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*4+(#a_01_2  & 1)*4+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_01_5  & 1)*3+(#a_00_6  & 1)*2+(#a_02_7  & 1)*2+(#a_00_8  & 1)*1) >=18
 
}