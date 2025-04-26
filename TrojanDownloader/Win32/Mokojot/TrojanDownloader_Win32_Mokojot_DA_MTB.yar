
rule TrojanDownloader_Win32_Mokojot_DA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Mokojot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 89 45 f4 8b 45 f8 31 d2 f7 75 0c 8b 45 f4 0f be 34 10 8b 45 10 8b 4d f8 0f be 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}