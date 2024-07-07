
rule Backdoor_Win32_Syskit_A{
	meta:
		description = "Backdoor:Win32/Syskit.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 20 00 26 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 2f 00 74 00 20 00 31 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 42 00 41 00 4b 00 2e 00 65 00 78 00 65 00 } //2 sc stop dllhost & timeout /t 10 & del C:\Windows\Temp\BAK.exe
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //2 powershell.exe
		$a_01_2 = {6b 69 6c 6c 5f 6d 65 } //2 kill_me
		$a_01_3 = {42 41 4b 2e 6e 65 74 34 2e 64 6c 6c 68 6f 73 74 2e 6d 61 69 6e 5c 42 41 4b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6d 73 63 6f 72 73 76 77 2e 70 64 62 } //10 BAK.net4.dllhost.main\BAK\obj\Release\mscorsvw.pdb
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 73 64 66 64 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 42 41 4b 2e 6e 65 74 34 5c 42 41 4b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 41 4b 2e 70 64 62 } //10 C:\Users\sdfd\Documents\Visual Studio 2015\Projects\BAK.net4\BAK\obj\Release\BAK.pdb
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 73 64 66 64 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 53 74 75 64 69 6f 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 42 41 4b 2e 6e 65 74 34 5c 42 41 4b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6d 73 63 6f 72 73 76 77 2e 70 64 62 } //10 C:\Users\sdfd\Documents\VisualStudio2015\Projects\BAK.net4\BAK\obj\Release\mscorsvw.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=16
 
}