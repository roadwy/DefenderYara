
rule TrojanDownloader_Win32_Lazy_RDB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Lazy.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 fc 81 7d fc 10 04 00 00 73 18 8b 4d fc 0f b6 91 ?? ?? ?? ?? 83 f2 61 8b 45 fc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}