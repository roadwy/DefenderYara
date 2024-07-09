
rule Trojan_Win32_Trickbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 39 4c ?? ?? 74 ?? 56 8b ?? ?? ?? 8b 74 ?? ?? 8b d1 03 c1 83 ?? ?? 8a ?? ?? 30 ?? 41 3b 4c ?? ?? 75 ?? 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}