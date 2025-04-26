
rule TrojanDownloader_Win32_Lotok_DG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Lotok.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 51 66 59 32 06 66 56 66 5e 88 07 9c 66 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}