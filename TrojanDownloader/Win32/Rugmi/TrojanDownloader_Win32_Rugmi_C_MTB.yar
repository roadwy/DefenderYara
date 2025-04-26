
rule TrojanDownloader_Win32_Rugmi_C_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c0 03 45 ?? 89 45 a4 8b 45 a4 8b ?? 33 85 58 ?? ?? ?? 8b 4d a4 89 01 8b 45 d4 83 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}