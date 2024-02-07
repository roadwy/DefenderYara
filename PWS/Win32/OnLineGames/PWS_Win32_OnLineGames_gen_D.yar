
rule PWS_Win32_OnLineGames_gen_D{
	meta:
		description = "PWS:Win32/OnLineGames.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  䐮䱌䐀汬慃啮汮慯乤睯
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 5c } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks\
		$a_02_2 = {3f 64 6f 3d 73 65 6e 64 26 47 61 6d 65 3d 90 02 05 26 53 65 72 76 65 72 3d 25 73 26 5a 6f 6e 65 3d 25 73 26 4e 61 6d 65 3d 25 73 26 50 61 73 73 3d 25 73 26 72 6f 6c 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 90 00 } //01 00 
		$a_00_3 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 } //00 00  regsvr32.exe /s
	condition:
		any of ($a_*)
 
}