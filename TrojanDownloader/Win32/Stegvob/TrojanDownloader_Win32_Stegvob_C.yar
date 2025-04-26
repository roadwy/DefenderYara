
rule TrojanDownloader_Win32_Stegvob_C{
	meta:
		description = "TrojanDownloader:Win32/Stegvob.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff ff 0f b7 9d ?? ?? ff ff 0f af cb 0f b7 85 ?? ?? ff ff 0f af c8 0f b7 95 ?? ?? ff ff 0f af ca 66 31 4d ba ff 4d ec } //5
		$a_03_1 = {83 7d bc 01 75 ?? c7 45 bc 02 00 00 00 83 6d c8 06 } //1
		$a_03_2 = {83 7d bc 03 75 ?? c7 45 bc 04 00 00 00 83 6d c8 06 } //1
		$a_03_3 = {83 7d bc 05 75 ?? c7 45 bc 06 00 00 00 83 6d c8 06 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}