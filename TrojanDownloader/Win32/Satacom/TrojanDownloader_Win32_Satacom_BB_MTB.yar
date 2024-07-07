
rule TrojanDownloader_Win32_Satacom_BB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Satacom.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c2 8b 4d 08 8b 11 03 d0 03 55 10 8b 45 0c 8b 08 2b ca 8b 55 0c 89 0a 8b 45 08 8b 4d 0c 8b 11 89 10 83 7d 90 01 02 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}