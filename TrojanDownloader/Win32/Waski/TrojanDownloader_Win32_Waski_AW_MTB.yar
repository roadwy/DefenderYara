
rule TrojanDownloader_Win32_Waski_AW_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8d 44 24 44 50 68 dc 21 40 00 50 ff 15 90 01 04 83 c4 10 8d 44 24 40 55 55 55 50 e9 90 01 04 56 33 f6 39 74 24 08 76 90 01 01 8a 04 16 88 04 0e 46 3b 74 24 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}