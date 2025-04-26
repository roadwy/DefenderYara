
rule Trojan_Win32_Qbot_PAT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 33 18 89 5d ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 03 5d a0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}