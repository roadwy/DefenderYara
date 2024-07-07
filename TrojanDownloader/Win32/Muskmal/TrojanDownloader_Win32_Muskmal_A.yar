
rule TrojanDownloader_Win32_Muskmal_A{
	meta:
		description = "TrojanDownloader:Win32/Muskmal.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 08 66 33 d1 e8 90 01 04 8b 95 dc fe ff ff 8b 45 f2 e8 90 01 04 8b 45 f2 33 c0 8a 45 ee 66 03 45 f6 66 69 c0 14 6f 66 05 6a 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}