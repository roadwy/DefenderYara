
rule TrojanDownloader_Win32_Delf_MI{
	meta:
		description = "TrojanDownloader:Win32/Delf.MI,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 00 31 00 2e 00 7a 00 69 00 70 00 } //1 t1.zip
		$a_01_1 = {73 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 69 00 76 00 63 00 65 00 } //1 schost.exe -runserivce
		$a_01_2 = {73 00 66 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 69 00 76 00 63 00 65 00 } //1 sfservice.exe -runserivce
		$a_01_3 = {43 00 61 00 72 00 61 00 20 00 64 00 65 00 20 00 50 00 61 00 75 00 } //1 Cara de Pau
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}