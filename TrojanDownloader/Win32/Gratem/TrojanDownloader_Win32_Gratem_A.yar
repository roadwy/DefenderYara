
rule TrojanDownloader_Win32_Gratem_A{
	meta:
		description = "TrojanDownloader:Win32/Gratem.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 f9 eb 75 90 01 01 0f b6 4a 01 33 c8 80 f9 02 75 90 01 01 0f b6 4a 02 33 c8 80 f9 cc 75 90 01 01 0f b6 4a 03 33 c8 80 f9 f1 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}