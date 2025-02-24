
rule Trojan_Win32_Snakelogger_SWA_MTB{
	meta:
		description = "Trojan:Win32/Snakelogger.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {71 75 61 6c 69 74 79 72 65 73 70 6f 6e 64 2e 65 78 65 } //2 qualityrespond.exe
		$a_01_1 = {77 65 78 74 72 61 63 74 2e 70 64 62 } //1 wextract.pdb
		$a_01_2 = {43 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 20 25 73 } //1 Command.com /c %s
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}