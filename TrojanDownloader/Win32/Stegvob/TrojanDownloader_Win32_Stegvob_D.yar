
rule TrojanDownloader_Win32_Stegvob_D{
	meta:
		description = "TrojanDownloader:Win32/Stegvob.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 bc 66 8b 94 45 9c db ff ff 66 31 55 b6 83 7d bc 05 75 } //1
		$a_03_1 = {83 7d c4 06 7d 90 01 01 8b 45 c4 66 8b 55 b6 66 89 94 45 9c db ff ff ff 45 c4 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}