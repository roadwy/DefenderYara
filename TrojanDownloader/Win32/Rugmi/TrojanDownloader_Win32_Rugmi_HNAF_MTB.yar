
rule TrojanDownloader_Win32_Rugmi_HNAF_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 51 3c 89 55 ?? 8b 45 90 1b 00 8b 4d ?? 03 48 2c 89 4d } //10
		$a_03_1 = {66 0f be 0c 02 8b 55 ?? 8b 45 ?? 66 89 0c 50 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}