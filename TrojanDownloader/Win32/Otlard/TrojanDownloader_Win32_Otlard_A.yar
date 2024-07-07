
rule TrojanDownloader_Win32_Otlard_A{
	meta:
		description = "TrojanDownloader:Win32/Otlard.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 45 ff 46 88 84 35 90 01 02 ff ff 8b c3 99 f7 f9 b1 03 8a c2 f6 e9 90 00 } //1
		$a_01_1 = {68 db d3 62 b5 89 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}