
rule Trojan_Win32_CobaltStrike_JKM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.JKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 02 88 54 24 ?? bf ?? ?? ?? ?? 31 d2 f7 f7 8b 04 24 89 d7 8a 54 24 ?? 32 14 3e 88 14 ?? 83 c0 ?? 31 d2 81 ea ?? ?? ?? ?? 31 c9 81 e9 ?? ?? ?? ?? 83 f8 ?? 0f 44 ca 89 4c 24 ?? 89 44 24 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}