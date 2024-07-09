
rule Trojan_Win32_Qbot_MS_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c2 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 90 09 06 00 8b 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}