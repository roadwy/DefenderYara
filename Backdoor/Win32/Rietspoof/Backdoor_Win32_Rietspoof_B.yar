
rule Backdoor_Win32_Rietspoof_B{
	meta:
		description = "Backdoor:Win32/Rietspoof.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 fc ff ff ff 2b c7 83 e0 07 8b 34 82 b8 fe ff ff ff 2b c7 83 e0 07 8b 0c 82 8b c7 f7 d0 83 e0 07 8d 1c 82 8b d6 c1 ca 0b 8b c6 c1 c0 07 33 d0 } //02 00 
		$a_00_1 = {4d 39 68 35 61 6e 38 66 38 7a 54 6a 6e 79 54 77 51 56 68 36 68 59 42 64 59 73 4d 71 48 69 41 7a 00 } //01 00 
		$a_02_2 = {73 79 73 74 65 6d 0a 00 90 02 06 25 73 25 73 25 73 20 55 53 45 52 3a 20 75 73 65 72 0a 00 90 00 } //00 00 
		$a_00_3 = {78 } //9f 00  x
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Rietspoof_B_2{
	meta:
		description = "Backdoor:Win32/Rietspoof.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 25 73 25 73 20 55 53 45 52 3a 20 75 73 65 72 } //01 00  %s%s%s USER: user
		$a_01_1 = {64 61 74 61 2e 64 61 74 } //01 00  data.dat
		$a_01_2 = {32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 } //01 00  2x%.2x%.2x%.2x%.2x%
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 44 65 6c 65 74 65 46 69 6c 65 28 57 73 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 29 } //01 00  CreateObject("Scripting.FileSystemObject").DeleteFile(Wscript.ScriptFullName)
		$a_01_4 = {63 6d 64 20 2f 63 20 25 73 } //00 00  cmd /c %s
	condition:
		any of ($a_*)
 
}