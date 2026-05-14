
rule Trojan_Win64_Rozena_SXB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 62 6a 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //2 Set objShell = CreateObject("WScript.Shell")
		$a_01_1 = {73 74 72 44 69 72 65 63 74 6f 72 79 20 3d 20 6f 62 6a 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 20 25 20 74 65 6d 70 20 25 20 22 29 } //1 strDirectory = objShell.ExpandEnvironmentStrings(" % temp % ")
		$a_01_2 = {64 69 6d 20 78 48 74 74 70 3a 20 53 65 74 20 78 48 74 74 70 20 3d 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //2 dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
		$a_01_3 = {64 69 6d 20 62 53 74 72 6d 3a 20 53 65 74 20 62 53 74 72 6d 20 3d 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //2 dim bStrm: Set bStrm = createobject("Adodb.Stream")
		$a_01_4 = {6f 62 6a 53 68 65 6c 6c 2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 44 65 73 6b 74 6f 70 57 61 6c 6c 70 61 70 65 72 22 2c 20 73 74 72 44 69 72 65 63 74 6f 72 79 20 2b 20 } //2 objShell.RegWrite "HKCUControl PanelDesktopWallpaper", strDirectory + 
		$a_01_5 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 22 20 25 20 77 69 6e 64 69 72 20 25 20 53 79 73 74 65 6d 33 32 52 55 4e 44 4c 4c 33 32 2e 45 58 45 20 75 73 65 72 33 32 2e 64 6c 6c 2c 20 55 70 64 61 74 65 50 65 72 55 73 65 72 53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 22 2c 20 31 2c 20 54 72 75 65 } //2 objShell.Run " % windir % System32RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters", 1, True
		$a_01_6 = {6e 65 74 73 74 61 74 20 2d 61 6e 6f 20 3e 20 6e 75 6c 20 32 3e 26 31 } //1 netstat -ano > nul 2>&1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=12
 
}