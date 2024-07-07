
rule TrojanDownloader_Win32_Karagany_H{
	meta:
		description = "TrojanDownloader:Win32/Karagany.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2e 70 68 70 3f 66 3d 25 69 26 74 3d 90 02 04 26 73 69 64 3d 25 73 90 00 } //1
		$a_01_1 = {64 8b 71 30 8b 76 0c 8b 76 1c 8b 46 08 89 45 fc 8b 7e 20 8b 36 80 3f 6b 74 07 80 3f 4b 74 02 eb e9 5f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}