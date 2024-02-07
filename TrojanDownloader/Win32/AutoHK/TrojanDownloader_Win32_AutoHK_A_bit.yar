
rule TrojanDownloader_Win32_AutoHK_A_bit{
	meta:
		description = "TrojanDownloader:Win32/AutoHK.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 48 52 2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 55 72 6c 2c 20 54 72 75 65 29 } //01 00  WHR.Open("GET", Url, True)
		$a_01_1 = {42 61 73 65 36 34 64 65 63 28 62 42 75 66 2c 62 42 75 66 66 65 72 29 } //01 00  Base64dec(bBuf,bBuffer)
		$a_01_2 = {42 61 73 65 36 34 64 65 63 28 4d 63 6f 64 65 2c 73 5f 41 53 4d 29 } //01 00  Base64dec(Mcode,s_ASM)
		$a_01_3 = {44 6c 6c 43 61 6c 6c 28 77 69 6e 73 2c 20 22 50 74 72 22 2c 20 26 4d 63 6f 64 65 2c 20 22 73 74 72 22 2c 20 54 61 72 67 65 74 48 6f 73 74 2c 20 22 50 74 72 22 2c 20 26 62 42 75 66 2c 20 22 55 69 6e 74 22 2c 20 30 2c 20 22 55 69 6e 74 22 2c 20 30 29 } //05 00  DllCall(wins, "Ptr", &Mcode, "str", TargetHost, "Ptr", &bBuf, "Uint", 0, "Uint", 0)
		$a_01_4 = {52 65 67 57 72 69 74 65 2c 20 52 45 47 5f 53 5a 2c 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 2c 20 75 70 64 2c 20 25 41 5f 54 65 6d 70 25 5c 25 41 5f 53 63 72 69 70 74 6e 61 6d 65 25 } //05 00  RegWrite, REG_SZ, HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce, upd, %A_Temp%\%A_Scriptname%
		$a_01_5 = {46 69 6c 65 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 2c 20 22 25 41 5f 54 65 6d 70 25 5c 25 41 5f 53 63 72 69 70 74 4e 61 6d 65 25 22 2c 20 25 41 5f 53 74 61 72 74 75 70 25 5c 47 6f 6c 75 70 64 61 74 65 2e 6c 6e 6b 2c 2c 2c 2c 31 } //00 00  FileCreateShortcut, "%A_Temp%\%A_ScriptName%", %A_Startup%\Golupdate.lnk,,,,1
	condition:
		any of ($a_*)
 
}