
rule TrojanDownloader_Win32_Tenega_JITA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.JITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 14 85 e0 f9 07 01 33 14 85 e4 f9 07 01 33 14 85 e8 f9 07 01 33 14 85 ec f9 07 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}