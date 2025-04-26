
rule TrojanDownloader_Win32_Banload_AOV{
	meta:
		description = "TrojanDownloader:Win32/Banload.AOV,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 74 5c 43 4c 53 49 44 5c } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Ext\CLSID\
		$a_01_1 = {46 6f 72 6d 5f 47 75 65 72 72 61 } //3 Form_Guerra
		$a_01_2 = {77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //2 www.google.com.br
		$a_01_3 = {55 50 70 72 6f 2e 64 6c 6c } //5 UPpro.dll
		$a_01_4 = {55 50 70 72 6f 2e 55 70 5f 43 6c 61 73 73 5c 43 6c 73 69 64 } //6 UPpro.Up_Class\Clsid
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*5+(#a_01_4  & 1)*6) >=19
 
}