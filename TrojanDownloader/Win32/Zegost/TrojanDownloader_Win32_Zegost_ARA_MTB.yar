
rule TrojanDownloader_Win32_Zegost_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zegost.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8a 14 08 80 c2 7a 88 14 08 8b 4c 24 08 8a 14 08 80 f2 59 88 14 08 40 3b c6 7c e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}