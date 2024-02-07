
rule Backdoor_Win32_Sharke_E{
	meta:
		description = "Backdoor:Win32/Sharke.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 73 00 68 00 61 00 72 00 6b 00 2d 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 6e 00 65 00 74 00 } //01 00  www.shark-project.net
		$a_01_1 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_2 = {41 6c 6c 6f 63 61 74 65 41 6e 64 47 65 74 54 63 70 45 78 54 61 62 6c 65 46 72 6f 6d 53 74 61 63 6b } //01 00  AllocateAndGetTcpExTableFromStack
		$a_01_3 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //01 00  EncryptString
		$a_00_4 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  wscript.shell
		$a_01_5 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //01 00  \system32\drivers\etc\hosts
		$a_01_6 = {53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //01 00  Scripting.FileSystemObject
		$a_01_7 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 22 00 } //01 00  cmd.exe /c "
		$a_01_8 = {5c 44 65 73 6b 74 6f 70 5c 53 68 61 72 6b 5c 50 72 6f 6a 65 6b 74 } //01 00  \Desktop\Shark\Projekt
		$a_01_9 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //00 00  capGetDriverDescriptionA
	condition:
		any of ($a_*)
 
}