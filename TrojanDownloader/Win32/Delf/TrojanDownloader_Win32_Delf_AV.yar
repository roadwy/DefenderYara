
rule TrojanDownloader_Win32_Delf_AV{
	meta:
		description = "TrojanDownloader:Win32/Delf.AV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {70 63 33 37 2f 74 61 6e 33 2e 70 68 70 } //1 pc37/tan3.php
		$a_01_2 = {5c 66 6c 61 73 68 70 6c 61 79 2e 64 6c 6c } //1 \flashplay.dll
		$a_01_3 = {5c 6d 73 5f 73 74 61 72 74 2e 65 78 65 } //1 \ms_start.exe
		$a_01_4 = {54 46 6f 72 6d 33 00 } //1
		$a_01_5 = {4f 6e 44 6f 77 6e 6c 6f 61 64 42 65 67 69 6e 5c 59 41 } //1 OnDownloadBegin\YA
		$a_01_6 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d } //1 shell\open\Command=
		$a_01_7 = {69 66 5f 70 2e 63 6c 69 63 6b 28 29 3b } //1 if_p.click();
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}