
rule Trojan_Win32_Agentb_MK_MTB{
	meta:
		description = "Trojan:Win32/Agentb.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 1c 0b 00 d3 0f b6 db 01 c3 32 1c 06 88 1c 06 00 d3 fe c3 0f b6 d3 41 3b 4c 24 10 bb 00 00 00 00 0f 44 cb 40 39 c7 } //20
		$a_01_1 = {0f be c0 89 fe c1 e6 05 01 f7 01 c7 0f b6 03 43 84 c0 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}