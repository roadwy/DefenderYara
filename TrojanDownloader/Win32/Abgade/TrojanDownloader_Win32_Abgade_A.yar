
rule TrojanDownloader_Win32_Abgade_A{
	meta:
		description = "TrojanDownloader:Win32/Abgade.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d bc 89 44 8d c0 eb c8 6a ff 6a 01 8d 55 c0 52 6a ?? ff 15 ?? ?? ?? ?? 6a 00 a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}