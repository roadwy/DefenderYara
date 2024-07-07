
rule TrojanDownloader_Win32_Autohoc_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Autohoc.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 07 00 00 "
		
	strings :
		$a_03_0 = {55 72 6c 20 3a 3d 20 22 68 74 74 70 90 02 30 2e 6a 70 67 90 00 } //5
		$a_01_1 = {77 69 6e 73 20 3a 3d 20 22 75 73 65 72 33 32 2e 64 6c 6c 5c 43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 } //10 wins := "user32.dll\CallWindowProcW
		$a_01_2 = {44 6c 6c 43 61 6c 6c 28 77 69 6e 73 2c 20 22 50 74 72 22 2c 20 26 4d 63 6f 64 65 2c 20 22 73 74 72 22 2c 20 54 61 72 67 65 74 48 6f 73 74 2c 20 22 50 74 72 22 2c 20 26 62 42 75 66 2c 20 22 55 69 6e 74 22 2c 20 30 2c 20 22 55 69 6e 74 22 2c 20 30 29 } //10 DllCall(wins, "Ptr", &Mcode, "str", TargetHost, "Ptr", &bBuf, "Uint", 0, "Uint", 0)
		$a_01_3 = {46 69 6c 65 43 6f 70 79 2c 25 41 5f 53 63 72 69 70 74 66 75 6c 6c 70 61 74 68 25 2c 20 25 41 5f 54 65 6d 70 25 5c 25 41 5f 53 63 72 69 70 74 6e 61 6d 65 25 2c 31 } //2 FileCopy,%A_Scriptfullpath%, %A_Temp%\%A_Scriptname%,1
		$a_01_4 = {46 69 6c 65 53 65 74 41 74 74 72 69 62 2c 20 2b 53 48 2c 20 25 41 5f 54 65 6d 70 25 5c 25 41 5f 53 63 72 69 70 74 6e 61 6d 65 25 2c 31 } //2 FileSetAttrib, +SH, %A_Temp%\%A_Scriptname%,1
		$a_01_5 = {52 65 67 57 72 69 74 65 2c 20 52 45 47 5f 53 5a 2c 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 RegWrite, REG_SZ, HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_6 = {46 69 6c 65 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 2c 20 22 25 41 5f 54 65 6d 70 25 5c 25 41 5f 53 63 72 69 70 74 4e 61 6d 65 25 22 2c 20 25 41 5f 53 74 61 72 74 75 70 25 } //1 FileCreateShortcut, "%A_Temp%\%A_ScriptName%", %A_Startup%
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=30
 
}