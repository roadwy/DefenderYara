
rule Trojan_Win32_Lazy_LR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_81_0 = {25 73 5c 5f 63 6c 65 61 6e 75 70 2e 62 61 74 } //1 %s\_cleanup.bat
		$a_81_1 = {25 73 2e 6f 6c 64 } //2 %s.old
		$a_81_2 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 42 20 22 25 73 22 } //3 wscript.exe /B "%s"
		$a_81_3 = {64 65 6c 20 22 25 73 22 20 3e 6e 75 6c 20 32 3e } //4 del "%s" >nul 2>
		$a_81_4 = {49 66 20 77 6d 69 2e 45 78 65 63 51 75 65 72 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 57 48 45 52 45 20 4e 61 6d 65 3d 27 22 } //5 If wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='"
		$a_81_5 = {53 65 74 20 77 6d 69 3d 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d } //6 Set wmi=GetObject("winmgmts:{impersonationLevel=impersonate}
		$a_81_6 = {4e 65 6b 6f 68 6c 20 53 72 65 76 69 65 73 } //7 Nekohl Srevies
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7) >=28
 
}