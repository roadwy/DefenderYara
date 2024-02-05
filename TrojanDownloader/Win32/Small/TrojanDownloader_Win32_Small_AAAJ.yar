
rule TrojanDownloader_Win32_Small_AAAJ{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 c4 f0 53 33 c9 89 4d f4 89 4d f0 89 55 f8 89 45 fc 8b 45 fc e8 cf af ff ff 8b 45 f8 e8 c7 af ff ff 33 c0 55 68 bf 70 00 10 64 ff 30 64 89 20 8d 55 f4 8b 45 f8 e8 de d3 ff ff 8b 45 f4 e8 b6 af ff ff 50 8d 55 f0 8b 45 fc e8 ca d3 ff ff 8b 45 f0 e8 a2 af ff ff 50 e8 f4 9f ff ff 50 e8 1a ba ff ff 8b d8 33 c0 5a 59 59 64 89 10 68 c6 70 00 10 8d 45 f0 ba 04 00 00 00 e8 42 ab ff ff c3 } //00 00 
	condition:
		any of ($a_*)
 
}