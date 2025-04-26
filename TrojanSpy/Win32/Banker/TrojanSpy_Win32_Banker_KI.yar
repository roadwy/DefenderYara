
rule TrojanSpy_Win32_Banker_KI{
	meta:
		description = "TrojanSpy:Win32/Banker.KI,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d } //1 MAIL FROM
		$a_01_2 = {52 43 50 54 20 54 4f } //1 RCPT TO
		$a_01_3 = {70 61 72 74 69 7a 61 6e 2e 65 78 65 2e 67 6f 6f 67 6c 65 70 61 67 65 73 2e 63 6f 6d } //1 partizan.exe.googlepages.com
		$a_01_4 = {32 45 33 43 33 36 35 31 2d 42 31 39 43 2d 34 44 44 39 2d 41 39 37 39 2d 39 30 31 45 43 33 45 39 33 30 41 46 } //1 2E3C3651-B19C-4DD9-A979-901EC3E930AF
		$a_01_5 = {6e 65 74 70 72 6f 66 69 6c 65 73 2e 63 6f 6d 2e 62 72 2f 74 6d 70 2f 65 6e 76 69 61 } //1 netprofiles.com.br/tmp/envia
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}