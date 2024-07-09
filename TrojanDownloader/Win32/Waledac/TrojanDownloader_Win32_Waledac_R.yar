
rule TrojanDownloader_Win32_Waledac_R{
	meta:
		description = "TrojanDownloader:Win32/Waledac.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf 00 90 01 00 eb 2d 7c 56 8b 45 fc } //1
		$a_03_1 = {50 ff 75 f8 e8 ?? ?? ?? ?? 59 59 84 c0 75 13 53 ff d7 ff 45 fc 83 7d fc 0a 7c ?? 32 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}