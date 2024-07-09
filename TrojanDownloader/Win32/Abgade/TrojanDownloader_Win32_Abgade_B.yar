
rule TrojanDownloader_Win32_Abgade_B{
	meta:
		description = "TrojanDownloader:Win32/Abgade.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d3 6a ff 6a 01 89 45 fc 8d 45 ec 50 6a ?? 5f 57 ff 15 ?? ?? ?? ?? 8d 75 ec ff 36 ff 15 ?? ?? ?? ?? 83 c6 04 4f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}