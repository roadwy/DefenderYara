
rule TrojanDownloader_Win32_Tiny_BM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 d8 31 db 31 c9 31 08 81 38 90 01 04 74 90 01 01 83 fb 00 75 90 01 01 31 08 41 eb ec 81 fb 10 03 00 00 73 90 01 01 83 c0 04 83 c3 04 eb dc 29 d8 ff 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}