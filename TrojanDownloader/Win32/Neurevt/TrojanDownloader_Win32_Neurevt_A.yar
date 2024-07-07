
rule TrojanDownloader_Win32_Neurevt_A{
	meta:
		description = "TrojanDownloader:Win32/Neurevt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 6c 00 64 00 72 00 2d 00 25 00 30 00 38 00 58 00 00 00 } //1
		$a_03_1 = {81 c1 a0 00 00 00 89 4d 90 01 01 8b 55 90 01 01 8b 45 0c 2b 42 34 89 45 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}