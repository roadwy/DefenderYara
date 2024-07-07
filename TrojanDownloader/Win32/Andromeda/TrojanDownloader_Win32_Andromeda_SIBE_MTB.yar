
rule TrojanDownloader_Win32_Andromeda_SIBE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f6 56 68 90 01 04 6a 90 01 01 56 6a 90 01 01 68 90 01 04 50 ff 15 90 01 04 a3 90 01 04 5f 83 f8 ff 74 90 01 01 56 68 90 01 04 53 ff 35 90 01 04 50 ff 15 90 01 04 a1 90 1b 08 0f b6 08 83 f1 90 01 01 39 35 90 1b 07 76 90 01 01 8a 14 30 32 d1 80 c2 90 01 01 88 14 30 46 3b 35 90 1b 07 72 90 01 01 ff d0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}