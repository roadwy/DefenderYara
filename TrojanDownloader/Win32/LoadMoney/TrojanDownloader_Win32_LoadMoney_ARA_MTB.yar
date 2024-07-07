
rule TrojanDownloader_Win32_LoadMoney_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/LoadMoney.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f3 0f b6 44 15 00 30 04 0e 83 c1 01 39 cf 75 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}