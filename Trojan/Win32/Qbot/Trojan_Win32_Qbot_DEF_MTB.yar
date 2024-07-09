
rule Trojan_Win32_Qbot_DEF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d 90 1b 00 89 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}