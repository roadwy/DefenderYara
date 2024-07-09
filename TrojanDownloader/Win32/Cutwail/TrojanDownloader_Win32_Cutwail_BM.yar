
rule TrojanDownloader_Win32_Cutwail_BM{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 01 01 01 01 51 8a c8 d3 c0 59 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 ?? ?? ?? ?? 72 03 89 45 f8 e2 d5 59 8b 5d f8 ac 32 c3 aa f7 c1 01 00 00 00 74 0b 85 c0 60 6a 01 e8 e5 01 00 00 61 } //1
		$a_00_1 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 e8 bf 01 00 00 85 c0 75 15 6a 40 68 00 30 00 00 ff 76 50 6a 00 e8 aa 01 00 00 85 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}