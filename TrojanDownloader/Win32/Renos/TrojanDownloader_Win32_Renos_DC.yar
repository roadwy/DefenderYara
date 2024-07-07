
rule TrojanDownloader_Win32_Renos_DC{
	meta:
		description = "TrojanDownloader:Win32/Renos.DC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 8a 4c 24 10 8d 44 24 10 84 c9 74 90 02 04 80 f1 90 01 01 88 08 8a 48 01 40 84 c9 75 f3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}