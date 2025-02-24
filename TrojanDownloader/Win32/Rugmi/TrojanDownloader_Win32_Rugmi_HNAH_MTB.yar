
rule TrojanDownloader_Win32_Rugmi_HNAH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ef 8b 4e 3c 8b 5f 04 8b 7f 08 03 74 31 2c [0-ff] [0-ff] c6 40 08 01 50 ff d3 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}