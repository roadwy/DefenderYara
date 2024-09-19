
rule TrojanDownloader_Win32_DCRat_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/DCRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b c8 8b 45 ?? 8b 10 8b 42 ?? 66 0f b6 14 18 33 ca } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}