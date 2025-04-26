
rule Trojan_Win32_Trickbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 02 8b 4d ?? 03 4d ?? 81 e1 ?? ?? ?? ?? 33 d2 8a 94 ?? ?? ?? ?? ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 e9 90 0a a4 00 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 ?? 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}