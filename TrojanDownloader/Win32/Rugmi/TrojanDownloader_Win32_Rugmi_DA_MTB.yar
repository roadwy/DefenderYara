
rule TrojanDownloader_Win32_Rugmi_DA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af 74 24 0c 0f b6 0c 3a 03 f1 42 3b d0 72 ?? 5f 8b c6 5e c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}