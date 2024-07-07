
rule TrojanDownloader_Win32_Pikabot_HU_MTB{
	meta:
		description = "TrojanDownloader:Win32/Pikabot.HU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a6 46 46 4e 81 95 90 01 08 10 35 90 01 04 98 b3 90 01 01 35 90 01 04 92 ad 1c 90 01 01 96 af 11 35 90 01 04 81 94 f4 90 01 08 46 84 98 90 01 04 78 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}