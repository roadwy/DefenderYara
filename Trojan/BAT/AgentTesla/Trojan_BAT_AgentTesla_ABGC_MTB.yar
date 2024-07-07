
rule Trojan_BAT_AgentTesla_ABGC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 13 05 08 13 06 11 05 11 06 3d 90 01 03 00 72 90 01 03 70 02 09 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 03 11 04 6f 90 01 03 0a 28 90 01 03 0a 6a 61 69 28 90 01 03 0a 28 90 01 03 0a 13 07 06 11 07 6f 90 01 03 0a 26 11 04 03 6f 90 01 03 0a 17 59 40 90 01 03 00 16 13 04 38 90 01 03 00 11 04 17 58 13 04 90 00 } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}