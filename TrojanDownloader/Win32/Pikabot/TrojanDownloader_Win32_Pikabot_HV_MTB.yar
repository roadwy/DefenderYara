
rule TrojanDownloader_Win32_Pikabot_HV_MTB{
	meta:
		description = "TrojanDownloader:Win32/Pikabot.HV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 43 b6 3c 90 01 01 66 c1 a2 90 01 05 c1 32 90 01 01 f1 80 d0 90 01 01 34 90 01 01 d2 d6 3d 90 01 04 63 d3 81 c5 90 01 04 30 cb 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}