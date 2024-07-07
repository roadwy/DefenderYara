
rule TrojanDownloader_Win32_Andromeda_SIBB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 56 53 ff d7 53 68 90 01 04 56 50 ff 35 90 01 04 a3 90 01 04 ff 55 90 01 01 a1 90 1b 02 8a 08 90 02 80 0f b6 c9 83 f1 90 01 01 90 02 80 33 f6 39 35 90 1b 00 76 90 01 01 a1 90 1b 02 8a 14 30 32 d1 80 c2 90 01 01 88 14 30 46 3b 35 90 1b 00 72 90 01 01 90 02 80 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}