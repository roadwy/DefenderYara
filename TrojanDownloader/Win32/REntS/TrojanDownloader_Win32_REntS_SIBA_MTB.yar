
rule TrojanDownloader_Win32_REntS_SIBA_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c0 64 8b 50 30 8b 52 0c 8b 52 90 01 01 8b 72 28 0f b7 4a 26 31 ff ac 3c 90 01 01 7c 90 01 01 2c 90 01 01 c1 cf 90 01 01 01 c7 e2 90 01 01 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 90 01 01 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 90 01 01 49 8b 34 8b 01 d6 31 ff ac c1 cf 90 01 01 01 c7 38 e0 75 90 01 01 03 7d 90 01 01 3b 7d 90 01 01 75 90 01 01 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}