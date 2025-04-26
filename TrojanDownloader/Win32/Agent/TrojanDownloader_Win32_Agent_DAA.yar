
rule TrojanDownloader_Win32_Agent_DAA{
	meta:
		description = "TrojanDownloader:Win32/Agent.DAA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 3b 3e 2d 2d 3e 00 } //1
		$a_01_1 = {7e 1b 8b 4c 24 04 8b 54 24 08 56 2b d1 8b f0 8a 04 0a 32 44 24 10 88 01 41 4e 75 f3 5e c3 } //1
		$a_03_2 = {68 1c 40 40 00 50 e8 ?? 0e 00 00 8d 85 e4 fe ff ff 50 8d 85 70 fa ff ff 50 e8 ?? 0d 00 00 8d 85 70 fa ff ff 68 14 40 40 00 50 e8 ?? 0d 00 00 83 c4 28 8d 45 e8 50 8d 85 a0 fe ff ff 50 53 53 53 53 53 8d 85 70 fa ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}