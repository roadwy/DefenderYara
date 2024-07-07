
rule TrojanDownloader_Win32_Upatre_DEB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Upatre.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 16 8a c1 b1 56 f6 e9 02 c2 83 ee 04 81 fe 90 01 04 8a c8 7f e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}