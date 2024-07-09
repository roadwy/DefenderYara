
rule Trojan_Win32_AgentTesla_CE_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 8a 84 05 [0-04] 30 04 19 41 89 4d fc 3b 4d 08 72 9b } //1
		$a_03_1 = {33 d2 88 8c 0d [0-04] 8b c1 f7 75 ?? 8a 04 3a 88 84 0d [0-04] 41 81 f9 00 01 00 00 7c df } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}