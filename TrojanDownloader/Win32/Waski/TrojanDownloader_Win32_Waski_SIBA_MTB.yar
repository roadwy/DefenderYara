
rule TrojanDownloader_Win32_Waski_SIBA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b ce 3b c8 74 90 01 01 ff 45 90 01 01 83 7d 90 1b 01 90 01 01 7c 90 01 01 83 7d 90 1b 01 90 1b 03 0f 84 90 01 04 80 3e 90 01 01 75 90 01 01 80 7e 90 01 02 75 90 01 01 80 7e 90 01 02 75 90 01 01 38 5e 90 01 01 75 90 01 01 c1 e0 90 01 01 50 6a 90 01 01 ff 75 90 01 01 ff 15 90 01 04 89 45 90 01 01 3b c3 0f 84 90 01 04 8b 7d 90 01 01 8b 45 90 01 01 8b 40 90 01 01 8b d7 33 c9 83 e7 90 01 01 c1 e2 90 01 01 41 89 5d 90 01 01 83 ff 90 01 01 76 90 01 01 31 04 8e 8b 7d 90 1b 16 41 c1 ef 90 01 01 3b cf 72 90 01 01 83 6d 90 1b 16 90 01 01 8d 45 90 1b 1b 50 ff 75 90 1b 16 83 c6 90 01 01 56 8b 75 90 1b 14 52 56 68 90 01 04 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}