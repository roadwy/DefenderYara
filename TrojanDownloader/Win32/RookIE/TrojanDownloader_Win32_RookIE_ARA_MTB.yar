
rule TrojanDownloader_Win32_RookIE_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/RookIE.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 84 c0 74 09 34 08 46 88 04 0a 41 eb f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}