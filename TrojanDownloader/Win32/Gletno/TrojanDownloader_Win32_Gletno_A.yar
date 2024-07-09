
rule TrojanDownloader_Win32_Gletno_A{
	meta:
		description = "TrojanDownloader:Win32/Gletno.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d3 50 ff d6 8b f8 8b 45 ?? 40 8b 00 89 45 ?? 8b c7 40 8b 00 89 45 ?? 8d 45 ?? 50 6a 40 6a 05 57 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}