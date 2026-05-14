
rule Trojan_Win64_Agentb_MK_MTB{
	meta:
		description = "Trojan:Win64/Agentb.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c8 45 03 c6 42 0f b6 84 19 a0 33 00 00 42 8a 84 18 20 32 00 00 41 88 04 12 49 03 d6 48 3b d3 } //20
		$a_01_1 = {48 8b 4b 08 41 8b d0 41 ff c0 0f b7 04 57 66 89 04 51 8b 43 10 44 3b c0 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}