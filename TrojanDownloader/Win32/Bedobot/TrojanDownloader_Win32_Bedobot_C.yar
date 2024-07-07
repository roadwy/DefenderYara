
rule TrojanDownloader_Win32_Bedobot_C{
	meta:
		description = "TrojanDownloader:Win32/Bedobot.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {2e 6d 61 69 00 90 02 10 2e 65 6d 6c 00 90 02 10 2e 74 62 62 00 90 02 10 2e 6d 62 6f 78 00 90 00 } //1
		$a_01_1 = {2e 70 68 70 3f 49 3d 31 00 } //1
		$a_03_2 = {74 1a 8d 4d 90 01 01 8b d3 8b 45 90 01 01 8b 38 ff 57 90 01 01 8b 55 90 01 01 b1 06 8b 45 90 01 01 e8 90 01 04 43 4e 0f 85 90 01 02 ff ff 90 00 } //2
		$a_03_3 = {75 0d 8d 45 90 01 01 ba 90 01 04 e8 90 01 04 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 48 0f 85 90 01 04 80 7d 90 01 01 01 75 04 b3 02 eb 02 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=5
 
}