
rule TrojanDownloader_Win32_Dofoil_A{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 8d 85 06 05 00 00 50 ff 95 d6 04 00 00 09 c0 74 24 89 c3 8d b5 ee 04 00 00 e8 ?? ?? 00 00 8d 9d 4e 05 00 00 8d 85 81 05 00 00 89 85 9e 05 00 00 e8 08 00 00 00 6a 00 ff 95 e6 04 00 00 8d bd a2 05 00 00 8d b5 1c 05 00 00 e8 ?? ?? 00 00 01 cf 4f 89 de e8 ?? ?? 00 00 8d 85 12 05 00 00 6a 00 6a 00 6a 00 6a 00 50 ff 95 ee 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}