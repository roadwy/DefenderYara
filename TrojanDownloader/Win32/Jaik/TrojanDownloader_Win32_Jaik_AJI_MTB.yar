
rule TrojanDownloader_Win32_Jaik_AJI_MTB{
	meta:
		description = "TrojanDownloader:Win32/Jaik.AJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4b 04 8b 45 fc 8b 14 39 81 7c 02 fc cc cc cc cc 75 12 8b 44 39 04 03 c2 8b 55 fc 81 3c 10 cc cc cc cc 74 10 ff 74 39 08 8b 45 04 50 e8 02 1b 9c ff 83 c4 08 46 83 c7 0c 3b 33 } //1
		$a_01_1 = {f8 c1 c0 03 66 f7 c1 df 13 66 85 e7 8d 80 85 fc 1e d0 f5 85 fc 35 37 72 e1 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}