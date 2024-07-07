
rule TrojanDownloader_Win32_Winical_A{
	meta:
		description = "TrojanDownloader:Win32/Winical.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7d f8 8b 45 10 0f be 14 10 33 ca 8b 45 fc 03 85 90 01 02 ff ff 88 08 eb b4 90 00 } //5
		$a_03_1 = {0c 7d 32 8b 90 01 01 08 03 90 00 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}