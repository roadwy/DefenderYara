
rule Trojan_Win32_Qbot_DSF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 33 f1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5e 5d c3 90 09 05 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}