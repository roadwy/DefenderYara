
rule TrojanDownloader_Win32_Rugmi_SB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 44 0d 08 30 04 32 8d 41 ?? 83 e9 ?? 42 f7 d9 1b c9 23 c8 3b d7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}