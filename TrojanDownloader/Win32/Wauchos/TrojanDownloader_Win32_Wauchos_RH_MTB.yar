
rule TrojanDownloader_Win32_Wauchos_RH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Wauchos.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 04 03 c7 8a 04 08 32 06 8b 4c 24 14 32 c3 43 88 04 0f 66 3b 5e 02 72 de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}