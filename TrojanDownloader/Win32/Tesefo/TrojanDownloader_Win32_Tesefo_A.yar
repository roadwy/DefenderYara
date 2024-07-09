
rule TrojanDownloader_Win32_Tesefo_A{
	meta:
		description = "TrojanDownloader:Win32/Tesefo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 25 b8 01 00 00 00 83 f8 06 7f 1b 80 7c 03 ff 30 74 10 b9 06 00 00 00 2b c8 bf 01 00 00 00 d3 e7 09 3e 40 4a 75 e0 } //1
		$a_03_1 = {ba 08 02 00 00 b8 12 00 00 00 e8 ?? ?? ?? ?? 50 8b 03 50 e8 ?? ?? ?? ?? 6a 00 8d 45 fc 50 6a 3e 8d 85 ca fa ff ff 50 8b 03 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}