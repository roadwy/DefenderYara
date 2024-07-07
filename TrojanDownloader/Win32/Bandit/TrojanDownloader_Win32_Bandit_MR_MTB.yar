
rule TrojanDownloader_Win32_Bandit_MR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bandit.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 31 81 fb 90 01 04 75 90 01 01 57 ff 15 90 01 04 8d 85 90 01 04 50 57 8d 85 90 01 04 50 57 ff 15 90 01 04 46 3b f3 7c 90 09 23 00 81 fb 90 01 04 75 90 01 01 8d 85 90 01 04 50 57 57 57 ff 15 90 01 04 e8 90 01 04 8b 8d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}