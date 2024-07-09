
rule TrojanDownloader_Win32_Hagkite_A{
	meta:
		description = "TrojanDownloader:Win32/Hagkite.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4c 04 50 40 83 f8 40 7c ed 68 ?? ?? ?? ?? e8 90 09 09 00 8a 88 ?? ?? ?? ?? 80 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}