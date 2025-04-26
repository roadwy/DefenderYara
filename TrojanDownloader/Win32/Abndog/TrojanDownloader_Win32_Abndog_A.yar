
rule TrojanDownloader_Win32_Abndog_A{
	meta:
		description = "TrojanDownloader:Win32/Abndog.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 b8 22 00 00 ff d7 6a 00 8d 44 24 10 6a 00 8d 8c 24 18 01 00 00 50 51 6a 00 e8 ?? ?? 00 00 85 c0 75 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}