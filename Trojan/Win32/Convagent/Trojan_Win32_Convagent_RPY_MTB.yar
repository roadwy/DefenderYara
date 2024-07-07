
rule Trojan_Win32_Convagent_RPY_MTB{
	meta:
		description = "Trojan:Win32/Convagent.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5c 24 18 8b c5 c1 e0 04 03 44 24 2c 8b f5 03 dd c1 ee 05 89 44 24 14 } //1
		$a_01_1 = {33 f3 33 f0 2b fe 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 8b 5c 24 18 } //1
		$a_01_2 = {8b 44 24 14 33 f3 33 c6 2b e8 89 44 24 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}