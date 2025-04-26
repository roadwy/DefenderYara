
rule TrojanDownloader_Win32_Banload_ADT{
	meta:
		description = "TrojanDownloader:Win32/Banload.ADT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 54 56 58 58 9d 44 44 44 44 44 56 9c 3f 51 d3 aa b5 94 ac } //1
		$a_01_1 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 6f 00 5c 00 } //1 C:\Tempo\
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}