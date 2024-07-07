
rule TrojanDownloader_Win32_Andromeda_SIBD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 50 6a 00 ff 55 90 01 01 a3 90 01 04 90 02 b0 6a 00 68 90 01 04 68 90 01 04 ff 35 90 1b 01 ff 35 90 01 04 ff 55 90 01 01 a1 90 1b 01 8a 00 88 45 90 01 01 90 02 b0 0f b6 45 90 1b 09 8b 35 90 1b 01 33 c9 83 f0 90 01 01 39 0d 90 1b 03 76 90 01 01 8a 14 0e 32 d0 80 c2 90 01 01 88 14 0e 41 3b 0d 90 1b 03 72 90 01 01 ff d6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}