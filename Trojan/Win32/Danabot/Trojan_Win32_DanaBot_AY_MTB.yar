
rule Trojan_Win32_DanaBot_AY_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 d3 e0 8b cf c1 e9 ?? 03 4d ?? 03 45 ?? 03 d7 33 c1 33 c2 29 45 ?? a1 [0-20] c7 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}