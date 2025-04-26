
rule Worm_Win32_Autorun_CX{
	meta:
		description = "Worm:Win32/Autorun.CX,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 6d 65 6e 61 5f 64 6f 6f 72 } //10 semena_door
		$a_00_1 = {2e 62 61 74 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //10 .bat C:\myapp.exe
		$a_00_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 43 3a 5c 57 49 4e 44 4f 57 53 } //10 cmd.exe /c C:\WINDOWS
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_02_4 = {2f 76 20 41 6e 74 69 76 69 72 75 7a 20 2f 64 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c [0-08] 2e 65 78 65 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*10) >=50
 
}
rule Worm_Win32_Autorun_CX_2{
	meta:
		description = "Worm:Win32/Autorun.CX,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 6d 65 6e 61 5f 64 6f 6f 72 } //10 semena_door
		$a_02_1 = {2e 62 61 74 [0-10] 40 73 68 69 66 74 } //10
		$a_00_2 = {72 65 67 20 61 64 64 20 22 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //10 reg add "hklm\software\microsoft\windows\currentversion\run
		$a_02_3 = {2f 76 20 41 6e 74 69 76 69 72 75 7a 20 2f 64 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c [0-08] 2e 65 78 65 } //10
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}