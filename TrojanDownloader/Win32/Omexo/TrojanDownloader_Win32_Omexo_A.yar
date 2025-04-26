
rule TrojanDownloader_Win32_Omexo_A{
	meta:
		description = "TrojanDownloader:Win32/Omexo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 0b 8b 51 50 52 50 ff 15 } //1
		$a_03_1 = {0f b6 14 08 88 54 24 03 80 74 24 03 ?? c0 4c 24 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}