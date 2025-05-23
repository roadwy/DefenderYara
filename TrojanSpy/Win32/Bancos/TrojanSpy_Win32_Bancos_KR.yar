
rule TrojanSpy_Win32_Bancos_KR{
	meta:
		description = "TrojanSpy:Win32/Bancos.KR,SIGNATURE_TYPE_PEHSTR,0a 00 09 00 0a 00 00 "
		
	strings :
		$a_01_0 = {52 43 50 54 20 54 4f 3a 3c } //1 RCPT TO:<
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //1 MAIL FROM:<
		$a_01_2 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //1 =_NextPart_2rfkindysadvnqw3nerasdf
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_01_4 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_01_5 = {43 4c 53 49 44 5c 7b 32 45 33 43 33 36 35 31 2d 42 31 39 43 2d 34 44 44 39 2d 41 39 37 39 2d 39 30 31 45 43 33 45 39 33 30 41 46 7d } //1 CLSID\{2E3C3651-B19C-4DD9-A979-901EC3E930AF}
		$a_01_6 = {43 4c 53 49 44 5c 7b 33 46 38 38 38 36 39 35 2d 39 42 34 31 2d 34 42 32 39 2d 39 46 34 34 2d 36 42 35 36 30 45 34 36 34 41 31 36 7d } //1 CLSID\{3F888695-9B41-4B29-9F44-6B560E464A16}
		$a_01_7 = {43 4c 53 49 44 5c 7b 39 45 43 33 30 32 30 34 2d 33 38 34 44 2d 31 31 44 33 2d 39 43 41 33 2d 30 30 41 30 32 34 46 30 41 46 30 33 7d } //1 CLSID\{9EC30204-384D-11D3-9CA3-00A024F0AF03}
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_9 = {47 70 66 53 4c 71 62 45 48 34 7a 4e 4b 72 6e 34 52 74 54 6b 52 36 7a 58 50 36 4c 61 38 35 31 6f 52 73 54 6f 4f 4d 71 57 48 63 62 69 50 4e 44 53 4b 71 44 47 4b 71 4c 37 42 61 62 45 48 57 } //1 GpfSLqbEH4zNKrn4RtTkR6zXP6La851oRsToOMqWHcbiPNDSKqDGKqL7BabEHW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=9
 
}