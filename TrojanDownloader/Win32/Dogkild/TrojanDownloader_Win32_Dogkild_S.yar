
rule TrojanDownloader_Win32_Dogkild_S{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 51 68 18 00 22 00 56 c7 45 f4 e8 03 00 00 } //1
		$a_01_1 = {75 00 8d 4c 24 0c 6a 00 51 68 80 20 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}