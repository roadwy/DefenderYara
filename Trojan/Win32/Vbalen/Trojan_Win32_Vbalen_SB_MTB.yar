
rule Trojan_Win32_Vbalen_SB_MTB{
	meta:
		description = "Trojan:Win32/Vbalen.SB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 76 62 5c 65 2e 62 61 74 } //1 F:\vb\e.bat
		$a_01_1 = {6d 61 6c 65 2e 41 74 74 61 63 68 6d 65 6e 74 73 2e 41 64 64 20 28 22 63 3a 5c 76 61 6c 65 2e 65 78 65 22 29 20 3e 6e 75 6c 20 3e 3e 43 3a 5c 76 61 6c 65 2e 76 62 73 } //1 male.Attachments.Add ("c:\vale.exe") >nul >>C:\vale.vbs
		$a_01_2 = {76 00 61 00 5c 00 56 00 61 00 6c 00 65 00 6e 00 74 00 69 00 6e 00 61 00 2e 00 76 00 62 00 70 00 } //1 va\Valentina.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}