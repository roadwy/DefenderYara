
rule TrojanDownloader_Win32_Mafchek_B{
	meta:
		description = "TrojanDownloader:Win32/Mafchek.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 dc e8 46 fd ff ff ff 75 dc ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 e0 ba 04 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}