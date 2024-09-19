
rule TrojanDownloader_Win32_Rugmi_EM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 c4 83 65 e0 00 83 65 dc 00 83 65 d8 00 6a 00 6a 00 6a 00 6a 01 8b 45 fc ff 70 48 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}