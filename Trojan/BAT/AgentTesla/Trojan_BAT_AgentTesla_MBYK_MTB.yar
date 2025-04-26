
rule Trojan_BAT_AgentTesla_MBYK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 02 09 6f ?? 00 00 0a 03 09 07 5d 6f ?? 00 00 0a 61 d1 9d 09 17 58 0d 09 } //1
		$a_01_1 = {52 4f 54 31 33 45 6e 63 6f 64 65 } //1 ROT13Encode
		$a_01_2 = {78 6f 72 53 74 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 xorStub.g.resources
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}