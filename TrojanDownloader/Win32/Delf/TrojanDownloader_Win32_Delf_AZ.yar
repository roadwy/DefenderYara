
rule TrojanDownloader_Win32_Delf_AZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.AZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 07 b9 ff ff 8b 55 f0 8d 45 f4 e8 ac b9 ff ff 46 4b 75 da } //1
		$a_00_1 = {38 49 40 00 4c 7d 40 00 cc 7b 40 00 00 00 00 00 04 7f 40 00 55 8b ec b9 } //1
		$a_02_2 = {ff ff 6a 00 6a 00 8d 4d 90 01 01 66 ba 90 01 05 40 00 e8 90 01 02 ff ff 8b 45 90 01 01 e8 90 01 02 ff ff 50 a1 90 01 01 a8 40 00 e8 90 01 02 ff ff 50 6a 00 e8 90 01 02 ff ff 8d 4d 90 01 01 66 ba 90 01 05 40 00 e8 90 01 02 ff ff 8b 45 90 01 01 50 8d 4d 90 01 01 66 ba 90 01 05 40 00 e8 90 01 02 ff ff 8b 45 90 01 01 5a e8 90 01 02 ff ff 8d 4d 90 01 01 66 ba 90 01 05 40 00 e8 90 01 01 fd ff ff 8b 45 90 01 01 33 d2 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 02 40 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}