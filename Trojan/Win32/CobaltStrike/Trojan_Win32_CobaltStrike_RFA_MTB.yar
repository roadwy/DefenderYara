
rule Trojan_Win32_CobaltStrike_RFA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a a5 08 00 c7 45 } //1
		$a_03_1 = {8b d8 83 c3 04 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 [0-05] c7 [0-05] 00 10 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}