
rule Trojan_Win32_Pikabot_PH_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 b8 01 00 00 00 6b c0 00 0f be 84 05 ?? ?? ?? ?? 6b c0 ?? be ?? 00 00 00 6b f6 ?? 0f be b4 35 ?? ?? ?? ?? 0f af c6 2b d0 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}