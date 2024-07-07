
rule Trojan_Win32_Kilim_A{
	meta:
		description = "Trojan:Win32/Kilim.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 25 77 65 62 25 2f 25 6b 69 6d 6c 69 6b 66 69 6c 65 25 } //1 URLDownloadToFile, %web%/%kimlikfile%
		$a_01_1 = {46 69 6c 65 43 72 65 61 74 65 44 69 72 2c 20 25 73 44 72 69 76 65 25 5c 57 69 6e 64 6f 77 73 5c 41 64 6f 62 65 46 6c 61 73 68 } //1 FileCreateDir, %sDrive%\Windows\AdobeFlash
		$a_01_2 = {61 70 70 20 61 70 70 69 64 3d 22 25 6b 69 6d 6c 69 6b 25 } //1 app appid="%kimlik%
		$a_01_3 = {52 75 6e 2c 20 25 73 44 72 69 76 65 25 5c 57 69 6e 64 6f 77 73 5c 41 64 6f 62 65 46 6c 61 73 68 5c 25 41 5f 53 63 72 69 70 74 4e 61 6d 65 25 } //1 Run, %sDrive%\Windows\AdobeFlash\%A_ScriptName%
		$a_01_4 = {44 6c 6c 43 61 6c 6c 28 53 68 65 6c 6c 45 78 65 63 75 74 65 2c 20 75 69 6e 74 2c 20 30 2c 20 73 74 72 2c 20 22 52 75 6e 41 73 22 2c } //1 DllCall(ShellExecute, uint, 0, str, "RunAs",
		$a_01_5 = {26 00 57 00 69 00 6e 00 64 00 6f 00 77 00 20 00 53 00 70 00 79 00 } //1 &Window Spy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}