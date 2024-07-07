
rule TrojanDownloader_Win32_Adload_AG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Adload.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 88 45 90 01 01 0f b6 45 90 01 01 8b 4d 90 01 01 0f b6 4c 0d 90 01 01 33 c1 8b 4d 90 01 01 8b 55 90 01 01 88 04 0a 90 09 25 00 8b 45 90 01 01 40 89 45 90 01 01 8b 45 90 01 01 39 45 90 01 01 73 90 01 01 8b 4d 90 01 01 c1 e1 90 01 01 8b 45 90 01 01 33 d2 f7 f1 89 55 90 01 01 8b 45 90 01 01 8b 4d 90 00 } //4
	condition:
		((#a_02_0  & 1)*4) >=4
 
}