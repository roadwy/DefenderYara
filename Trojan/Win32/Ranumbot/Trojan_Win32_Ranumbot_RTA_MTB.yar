
rule Trojan_Win32_Ranumbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e ?? 8b 2d ?? ?? ?? ?? 8d 9b ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 81 ff 71 11 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}