
rule TrojanDownloader_Win32_Nymaim_C{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {59 5b 5e 5f 8b 4d 0c 83 c1 04 c1 e1 02 8b 55 10 c9 01 cc ff e2 } //01 00 
		$a_00_1 = {88 07 47 46 08 c0 75 e1 89 f8 5f 5e 59 c9 c2 08 00 } //01 00 
		$a_02_2 = {83 7c 24 04 90 01 01 0f 85 90 01 02 ff ff 89 4c 24 04 c3 90 00 } //01 00 
		$a_02_3 = {89 c2 58 89 f9 81 e9 90 01 04 51 c1 e9 02 83 f9 00 74 05 01 d3 49 75 fb 59 83 e1 03 c1 e1 03 d3 cb 8a 07 30 d8 59 5f 5b 5a c9 c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}