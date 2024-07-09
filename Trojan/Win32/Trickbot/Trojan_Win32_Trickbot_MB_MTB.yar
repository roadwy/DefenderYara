
rule Trojan_Win32_Trickbot_MB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c1 f7 f7 8a 5c 0c ?? 0f b6 c3 41 0f b6 14 2a 03 d6 03 c2 33 d2 be ?? ?? ?? ?? f7 f6 8b f2 8a 44 34 ?? 88 44 0c ?? 88 5c 34 ?? 81 f9 90 1b 01 72 cb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}