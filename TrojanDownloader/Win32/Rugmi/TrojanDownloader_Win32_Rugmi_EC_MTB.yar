
rule TrojanDownloader_Win32_Rugmi_EC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 0c 8b 4d f8 8b 51 18 03 55 f4 89 55 f4 8b 45 f8 8b 48 10 39 4d f4 73 15 8b 55 e8 03 55 f4 8b 02 03 45 dc 8b 4d f0 03 4d f4 89 01 eb d4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}