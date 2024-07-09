
rule TrojanDownloader_Win32_Discpy_A{
	meta:
		description = "TrojanDownloader:Win32/Discpy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 8b 55 ?? 8b 42 0c ff d0 } //1
		$a_01_1 = {03 55 0c 8b 5a 20 03 5d 0c 8b 4a 18 8b 33 03 75 0c 6a 00 56 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}