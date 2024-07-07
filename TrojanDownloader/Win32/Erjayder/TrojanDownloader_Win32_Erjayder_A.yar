
rule TrojanDownloader_Win32_Erjayder_A{
	meta:
		description = "TrojanDownloader:Win32/Erjayder.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 50 45 47 20 45 72 72 6f 72 21 00 90 02 20 2e 65 78 65 90 02 10 68 74 74 70 3a 2f 2f 90 02 50 2e 6a 70 67 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}