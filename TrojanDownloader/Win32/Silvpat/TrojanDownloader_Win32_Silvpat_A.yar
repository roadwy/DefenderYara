
rule TrojanDownloader_Win32_Silvpat_A{
	meta:
		description = "TrojanDownloader:Win32/Silvpat.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 3e e9 74 15 b9 ?? ?? ?? ?? 33 db ac 34 22 aa e2 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}