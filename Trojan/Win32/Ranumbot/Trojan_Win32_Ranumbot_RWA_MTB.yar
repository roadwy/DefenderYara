
rule Trojan_Win32_Ranumbot_RWA_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 5d 5e 81 ff 71 11 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}