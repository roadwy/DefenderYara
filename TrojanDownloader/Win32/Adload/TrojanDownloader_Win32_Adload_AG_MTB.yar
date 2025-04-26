
rule TrojanDownloader_Win32_Adload_AG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Adload.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 88 45 ?? 0f b6 45 ?? 8b 4d ?? 0f b6 4c 0d ?? 33 c1 8b 4d ?? 8b 55 ?? 88 04 0a 90 09 25 00 8b 45 ?? 40 89 45 ?? 8b 45 ?? 39 45 ?? 73 ?? 8b 4d ?? c1 e1 ?? 8b 45 ?? 33 d2 f7 f1 89 55 ?? 8b 45 ?? 8b 4d } //4
	condition:
		((#a_02_0  & 1)*4) >=4
 
}