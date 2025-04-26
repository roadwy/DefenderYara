
rule TrojanDownloader_Win32_Lotok_DH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Lotok.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 06 60 fd 89 c8 52 5b fc 61 88 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}