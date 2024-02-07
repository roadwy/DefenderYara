
rule Ransom_Win32_Rozbeh_AN_MTB{
	meta:
		description = "Ransom:Win32/Rozbeh.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 20 2f 66 20 25 25 25 25 46 20 69 6e 20 28 27 64 69 72 20 2a 2e 65 78 65 20 2f 73 20 2f 62 27 29 20 64 6f 20 63 6f 70 79 20 2f 79 20 52 6f 7a 62 65 68 2e 65 78 65 } //01 00  for /f %%%%F in ('dir *.exe /s /b') do copy /y Rozbeh.exe
		$a_01_1 = {52 6f 7a 62 65 68 2e 62 61 74 } //01 00  Rozbeh.bat
		$a_01_2 = {44 65 73 6b 46 4c 2e 76 62 73 } //01 00  DeskFL.vbs
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 2f 79 20 2e 2e 5c 52 6f 7a 62 65 68 2e 65 78 65 20 25 25 41 70 70 44 61 74 61 25 25 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //01 00  cmd.exe /c copy /y ..\Rozbeh.exe %%AppData%%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
		$a_01_4 = {53 63 61 6e 6e 65 72 2e 62 61 74 } //00 00  Scanner.bat
	condition:
		any of ($a_*)
 
}