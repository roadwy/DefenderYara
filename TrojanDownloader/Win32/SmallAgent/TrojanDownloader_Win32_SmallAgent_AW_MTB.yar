
rule TrojanDownloader_Win32_SmallAgent_AW_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 01 00 00 73 25 8b 45 08 03 45 fc 8a 4d fc 88 08 8b 45 fc 33 d2 f7 75 10 8b 45 fc 8b 4d 0c 8a 14 11 88 94 05 f8 fe ff ff eb c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}