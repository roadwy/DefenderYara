
rule TrojanDownloader_Win32_Waski_SIBC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5d 8b f5 b9 90 01 04 ad 90 18 60 90 18 8b e8 8b f3 b9 10 00 00 00 e8 90 01 04 b9 1f 00 00 00 e8 90 01 04 56 b9 07 00 00 00 e8 90 01 04 8b d0 8b 34 24 b9 09 00 00 00 e8 90 01 04 8b fe 8b ca e8 90 01 04 33 c0 50 c1 c8 90 01 01 c1 04 24 90 01 01 01 04 24 ac 84 c0 75 90 01 01 58 8b f7 3b c5 74 90 01 01 4a 75 90 01 01 8b 34 24 b9 0a 00 00 00 e8 90 01 04 0f b7 0c 56 5e 51 b9 08 00 00 00 e8 90 01 04 59 e8 90 01 04 89 74 24 90 01 01 61 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}