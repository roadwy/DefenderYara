
rule TrojanDownloader_Win32_AsyncRat_CCIQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRat.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 04 82 30 01 8b 4d f8 8b 46 04 41 2b 06 89 4d f8 3b c8 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}