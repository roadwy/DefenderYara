
rule TrojanDownloader_Win32_Cordmix_A{
	meta:
		description = "TrojanDownloader:Win32/Cordmix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ac 34 78 34 73 aa e2 f8 c9 } //1
		$a_01_1 = {68 52 b8 8e 7c 50 e8 } //1
		$a_01_2 = {bb 3e 22 00 00 81 f3 73 78 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}