
rule Trojan_Win32_AgentTesla_RDH_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 75 14 c1 ea 02 8b 4d 08 0f be 04 11 6b c0 43 6b c0 37 99 b9 22 00 00 00 f7 f9 6b c0 16 99 b9 22 00 00 00 f7 f9 8b 55 0c 03 55 e0 0f be 0a 33 c8 } //2
		$a_01_1 = {46 00 72 00 65 00 71 00 75 00 65 00 6e 00 63 00 79 00 } //1 Frequency
		$a_01_2 = {57 00 68 00 6f 00 6c 00 6c 00 79 00 } //1 Wholly
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 64 00 6f 00 74 00 20 00 73 00 63 00 68 00 6f 00 6c 00 61 00 73 00 74 00 69 00 63 00 69 00 73 00 6d 00 } //1 Microdot scholasticism
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}