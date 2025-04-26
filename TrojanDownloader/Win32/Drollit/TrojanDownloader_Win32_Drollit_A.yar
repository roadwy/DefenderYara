
rule TrojanDownloader_Win32_Drollit_A{
	meta:
		description = "TrojanDownloader:Win32/Drollit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d0 8b f0 3b f3 74 4d 8d 45 e0 50 56 68 a5 c0 61 e8 e8 ?? ?? ff ff ff d0 85 c0 74 0a 83 7d e4 04 75 04 b3 01 eb 2e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}