
rule Trojan_Win32_Qbot_DED_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 23 8b 4c 24 1c 88 01 8b 4c 24 14 41 31 d2 89 54 24 34 89 54 24 30 89 4c 24 18 8b 54 24 0c 39 d1 74 ?? eb ?? 8b 44 24 24 35 ?? ?? ?? ?? 89 44 24 18 8b 44 24 30 8b 4c 24 34 05 ?? ?? ?? ?? 83 d1 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}