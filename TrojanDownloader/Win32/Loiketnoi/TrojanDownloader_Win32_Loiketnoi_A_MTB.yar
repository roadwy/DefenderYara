
rule TrojanDownloader_Win32_Loiketnoi_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Loiketnoi.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 00 89 c2 c7 44 24 08 10 00 00 00 8d 45 90 01 01 89 44 24 04 89 14 24 a1 90 01 02 40 00 ff d0 83 ec 0c 85 c0 90 01 02 c7 04 24 90 01 04 a1 90 01 02 40 00 ff d0 83 ec 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}