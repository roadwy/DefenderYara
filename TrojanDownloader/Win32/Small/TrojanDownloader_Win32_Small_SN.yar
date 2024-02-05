
rule TrojanDownloader_Win32_Small_SN{
	meta:
		description = "TrojanDownloader:Win32/Small.SN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 00 8b d0 d1 e0 33 c2 83 c0 21 5a 89 02 c1 e8 18 5a c3 ba 05 02 40 00 b9 bb 06 00 00 e8 d7 ff ff ff 30 02 42 e2 f6 e9 58 fc ff ff ff 25 } //00 00 
	condition:
		any of ($a_*)
 
}