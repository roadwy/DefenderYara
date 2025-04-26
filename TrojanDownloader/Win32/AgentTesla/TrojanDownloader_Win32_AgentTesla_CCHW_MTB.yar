
rule TrojanDownloader_Win32_AgentTesla_CCHW_MTB{
	meta:
		description = "TrojanDownloader:Win32/AgentTesla.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 1a 8a 1c 31 32 d3 8b 5d ?? 88 14 01 b8 01 00 00 00 03 c7 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}