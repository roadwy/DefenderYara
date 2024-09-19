
rule TrojanDownloader_Win32_AsyncRat_CCJB_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRat.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 16 8b 49 0c 8b 42 0c 8b 55 a4 8a 04 10 8b 55 d4 32 04 1a 8b 55 a0 88 04 11 8b 45 e8 83 c0 01 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}