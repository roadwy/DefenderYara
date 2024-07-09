
rule Trojan_Win32_Qbot_PVE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ff 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 8b e5 5d c3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}