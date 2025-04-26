
rule TrojanDownloader_Win32_Upatre_CQ{
	meta:
		description = "TrojanDownloader:Win32/Upatre.CQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 39 68 01 01 00 00 6a 1d 6a 2d 68 00 00 cf 00 68 00 30 40 00 68 2b 30 40 00 6a 00 b9 a3 63 98 00 e8 ?? ?? ?? ?? 51 c3 85 c0 74 23 } //1
		$a_03_1 = {6a 39 68 01 01 00 00 6a 1d 6a 2d 68 00 00 cf 00 68 00 30 40 00 68 2b 30 40 00 6a 00 b9 69 88 5b 00 e8 ?? ?? ?? ?? 51 c3 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}