
rule Virus_Win32_Proyo{
	meta:
		description = "Virus:Win32/Proyo,SIGNATURE_TYPE_PEHSTR_EXT,4d 01 4d 01 0f 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {7b 34 44 33 36 45 39 36 37 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d } //100 {4D36E967-E325-11CE-BFC1-08002BE10318}
		$a_00_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 78 70 6c 6f 72 65 72 } //100 cmd.exe /c explorer
		$a_00_3 = {5c 6f 79 6f 2e 65 78 65 } //10 \oyo.exe
		$a_00_4 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 \autorun.inf
		$a_00_5 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 } //10 Explorer.EXE
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_8 = {61 76 70 2e 65 78 65 } //1 avp.exe
		$a_01_9 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_00_10 = {49 63 65 53 77 6f 72 64 2e 65 78 65 } //1 IceSword.exe
		$a_00_11 = {52 61 76 4d 6f 6e 2e 65 78 65 } //1 RavMon.exe
		$a_00_12 = {6e 6f 64 33 32 2e 65 78 65 } //1 nod32.exe
		$a_00_13 = {6e 6f 64 33 32 6b 72 6e 2e 65 78 65 } //1 nod32krn.exe
		$a_00_14 = {6e 6f 64 33 32 6b 75 69 2e 65 78 65 } //1 nod32kui.exe
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=333
 
}