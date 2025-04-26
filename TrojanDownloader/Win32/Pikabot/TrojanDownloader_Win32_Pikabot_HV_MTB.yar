
rule TrojanDownloader_Win32_Pikabot_HV_MTB{
	meta:
		description = "TrojanDownloader:Win32/Pikabot.HV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 43 b6 3c ?? 66 c1 a2 ?? ?? ?? ?? ?? c1 32 ?? f1 80 d0 ?? 34 ?? d2 d6 3d ?? ?? ?? ?? 63 d3 81 c5 ?? ?? ?? ?? 30 cb 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}