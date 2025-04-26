
rule TrojanDownloader_Win32_Upatre_AN{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {b0 2d 66 ab b0 53 66 ab b0 50 66 ab 58 04 30 66 ab 33 c0 b0 2f 66 ab } //1
		$a_01_1 = {b0 53 66 ab b0 45 66 ab b0 52 66 ab 83 ee 07 66 ad 66 85 c0 74 12 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}