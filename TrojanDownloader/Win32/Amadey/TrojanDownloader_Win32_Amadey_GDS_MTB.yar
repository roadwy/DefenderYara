
rule TrojanDownloader_Win32_Amadey_GDS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Amadey.GDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 43 ca 03 c1 3b f0 74 59 8b 45 e0 8b 57 10 8a 0c 30 32 0e 88 4d f0 3b 57 14 73 26 83 7f 14 10 8d 42 01 89 47 10 8b c7 72 90 01 01 8b 07 88 0c 10 46 c6 44 10 01 00 a1 90 01 04 8b 15 90 01 04 eb 90 00 } //10
		$a_01_1 = {41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //1 Amadey\Release\Amadey.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}