
rule TrojanDownloader_Win32_Renos_LS{
	meta:
		description = "TrojanDownloader:Win32/Renos.LS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {05 72 06 00 00 05 df 1a 00 00 35 65 18 00 00 19 c0 11 c0 85 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}