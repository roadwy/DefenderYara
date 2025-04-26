
rule Trojan_Win32_AgentTesla_ST_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {10 b1 f8 40 [0-04] 81 c1 90 20 39 cb 75 ?? 38 ed } //1
		$a_03_1 = {68 80 54 00 00 [0-06] 5b ?? ?? 83 eb 02 [0-06] 83 eb 02 ?? ?? 8b 14 1f [0-18] 31 f2 [0-30] 09 14 18 [0-15] 7f [0-10] 89 c2 [0-10] c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}