
rule TrojanDownloader_Win32_Banker{
	meta:
		description = "TrojanDownloader:Win32/Banker,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 56 8b f0 6a 00 a1 90 01 04 8b 00 8b 40 30 50 e8 90 01 04 e8 90 01 04 e8 90 01 04 68 ff ff 00 00 b9 90 01 04 b2 01 a1 90 01 04 e8 90 01 04 8b d8 e8 90 01 04 e8 90 01 04 8b cb ba 90 01 04 8b 86 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 8b c3 e8 90 01 04 e8 90 00 } //2
		$a_02_1 = {72 61 66 61 73 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f 90 02 10 2e 74 6d 70 90 00 } //1
		$a_02_2 = {63 6d 64 20 2f 6b 20 63 3a 5c 78 78 90 02 06 2e 65 78 65 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=4
 
}