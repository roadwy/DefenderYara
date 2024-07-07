
rule TrojanDownloader_Win32_Moure_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Moure.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 78 12 33 c0 5d c2 0f } //5
		$a_01_1 = {81 78 0a 90 90 c3 90 0f } //5
		$a_01_2 = {03 00 41 00 56 00 49 00 } //1
		$a_01_3 = {81 78 0a b8 00 00 00 0f } //5
		$a_01_4 = {81 78 0e 00 c2 2c 00 0f } //5
		$a_01_5 = {81 78 0e 00 c2 40 00 0f } //5
		$a_01_6 = {81 78 0d 00 c2 40 00 0f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=6
 
}