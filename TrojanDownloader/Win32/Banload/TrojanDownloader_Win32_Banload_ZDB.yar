
rule TrojanDownloader_Win32_Banload_ZDB{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZDB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be ff ff ff ff 0f bf c8 80 84 32 90 01 05 90 18 81 f7 90 01 04 81 d9 90 01 04 4d 80 cd ff bb 90 01 04 b9 90 01 04 81 ea 01 00 00 00 81 f7 90 01 04 be 90 01 04 8b dd 0f bf fb 81 fb 90 01 04 0f 90 01 02 ff ff ff e9 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}