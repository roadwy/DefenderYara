
rule Backdoor_Win32_Idicaf_gen_A{
	meta:
		description = "Backdoor:Win32/Idicaf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0e 00 00 ffffff9c ffffffff "
		
	strings :
		$a_01_0 = {5c 53 69 6d 70 6c 79 20 53 75 70 65 72 20 53 6f 66 74 77 61 72 65 5c 54 72 6f 6a 61 6e 20 52 65 6d 6f 76 65 72 5c } //14 00  \Simply Super Software\Trojan Remover\
		$a_00_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 } //01 00 
		$a_00_2 = {49 6e 6a 65 63 74 } //01 00  Inject
		$a_00_3 = {4b 65 79 4c 6f 67 } //01 00  KeyLog
		$a_00_4 = {73 68 75 74 64 6f 77 6e } //01 00  shutdown
		$a_00_5 = {6c 6f 67 6f 6e 75 69 2e 65 78 65 } //01 00  logonui.exe
		$a_00_6 = {72 75 6e 64 6c 6c 36 34 2e 65 78 65 } //01 00  rundll64.exe
		$a_00_7 = {64 65 6c 68 6f 73 74 69 6e 66 6f } //01 00  delhostinfo
		$a_00_8 = {25 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //01 00  %s\IEXPLORE.EXE
		$a_00_9 = {64 65 6c 20 22 25 73 } //01 00  del "%s
		$a_00_10 = {5c 76 6d 73 65 6c 66 64 65 6c 2e 62 61 74 } //01 00  \vmselfdel.bat
		$a_00_11 = {61 74 74 72 69 62 20 2d 61 20 2d 72 20 2d 73 20 2d 68 20 22 25 73 } //01 00  attrib -a -r -s -h "%s
		$a_00_12 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c } //01 00  if exist "%s" goto selfkill
		$a_00_13 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
	condition:
		any of ($a_*)
 
}