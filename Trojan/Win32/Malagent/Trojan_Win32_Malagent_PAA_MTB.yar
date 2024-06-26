
rule Trojan_Win32_Malagent_PAA_MTB{
	meta:
		description = "Trojan:Win32/Malagent.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 42 5f 47 61 64 67 65 74 53 74 61 63 6b 5f 90 02 04 69 90 00 } //01 00 
		$a_03_1 = {43 3a 5c 54 45 4d 50 5c 90 02 04 2e 74 6d 70 90 00 } //01 00 
		$a_01_2 = {44 65 62 75 67 67 65 72 20 62 72 65 61 6b 70 6f 69 6e 74 20 72 65 61 63 68 65 64 } //01 00  Debugger breakpoint reached
		$a_01_3 = {2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e } //01 00  -NonI -W Hidden -Comman
		$a_01_4 = {2e 00 74 00 6d 00 70 00 62 00 32 00 65 00 74 00 65 00 6d 00 70 00 66 00 69 00 6c 00 65 00 } //01 00  .tmpb2etempfile
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //01 00  ShellExecuteExA
		$a_01_6 = {52 65 76 6f 6b 65 44 72 61 67 44 72 6f 70 } //01 00  RevokeDragDrop
		$a_01_7 = {53 79 73 49 50 41 64 64 72 65 73 73 33 32 } //01 00  SysIPAddress32
		$a_01_8 = {4d 44 49 5f 43 68 69 6c 64 43 6c 61 73 73 } //01 00  MDI_ChildClass
		$a_01_9 = {50 42 5f 48 6f 74 6b 65 79 } //01 00  PB_Hotkey
		$a_01_10 = {2e 62 61 74 } //01 00  .bat
		$a_01_11 = {5c 5c 3f 5c } //00 00  \\?\
	condition:
		any of ($a_*)
 
}