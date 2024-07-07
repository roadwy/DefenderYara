
rule Worm_Win32_Autorun_NO{
	meta:
		description = "Worm:Win32/Autorun.NO,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 57 72 69 74 65 20 28 24 44 73 6b 50 61 74 68 20 26 20 22 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 22 2c 20 22 61 75 74 6f 72 75 6e 22 2c 20 22 73 68 65 6c 6c 5c 41 75 74 6f 70 6c 61 79 5c 43 6f 6d 6d 61 6e 64 22 2c } //1 IniWrite ($DskPath & "\autorun.inf", "autorun", "shell\Autoplay\Command",
		$a_01_1 = {49 66 20 50 72 6f 63 65 73 73 45 78 69 73 74 73 28 22 45 78 70 6c 6f 72 65 72 2e 65 78 65 22 29 3d 30 20 54 68 65 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 22 45 78 70 6c 6f 72 65 72 2e 65 78 65 22 2c 20 22 22 2c 20 40 57 69 6e 64 6f 77 73 44 69 72 2c 22 6f 70 65 6e 22 29 } //1 If ProcessExists("Explorer.exe")=0 Then ShellExecute("Explorer.exe", "", @WindowsDir,"open")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}