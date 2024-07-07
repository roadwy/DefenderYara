
rule Trojan_BAT_AgentTesla_PSHM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 53 00 00 06 0a 06 28 95 00 00 0a 7d 46 00 00 04 06 02 7d 48 00 00 04 06 03 7d 47 00 00 04 06 15 7d 45 00 00 04 06 7c 46 00 00 04 12 00 28 05 00 00 2b 06 7c 46 00 00 04 28 97 00 00 0a 2a } //2
		$a_01_1 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}