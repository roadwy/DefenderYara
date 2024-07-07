
rule TrojanDownloader_Win32_Convagent_AW_MTB{
	meta:
		description = "TrojanDownloader:Win32/Convagent.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 98 8b 45 98 8a 08 88 4d b8 0f be 45 b8 99 33 85 90 02 04 8b 55 98 88 02 e9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}