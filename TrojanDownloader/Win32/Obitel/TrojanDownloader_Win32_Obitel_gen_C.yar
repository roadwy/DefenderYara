
rule TrojanDownloader_Win32_Obitel_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Obitel.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 07 3d 68 74 74 70 75 } //2
		$a_01_1 = {32 f2 88 33 43 } //1
		$a_01_2 = {8a 21 32 e0 88 21 } //1
		$a_01_3 = {8a 02 83 f0 00 3d cc 00 00 00 75 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}