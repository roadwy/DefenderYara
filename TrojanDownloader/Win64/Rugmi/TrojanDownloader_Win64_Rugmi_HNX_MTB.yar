
rule TrojanDownloader_Win64_Rugmi_HNX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 49 3c 48 01 c8 [0-30] 8b 49 2c 48 01 c8 [0-a0] ff d0 [0-d0] 48 8b 84 24 ?? 00 00 00 48 89 84 24 ?? 00 00 00 48 8d 8c 24 ?? ?? 00 00 ff 94 24 90 1b 04 00 00 00 } //4
		$a_03_1 = {0f be 04 08 48 8b 4c 24 ?? ?? ?? ?? ?? 66 89 04 51 8b 44 24 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}