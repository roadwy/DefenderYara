
rule Trojan_BAT_AgentTesla_MBDM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //1
		$a_01_1 = {37 33 37 35 31 64 38 31 2d 33 37 39 66 2d 34 39 34 39 2d 61 34 66 63 2d 38 61 38 66 66 62 35 34 32 37 39 37 } //1 73751d81-379f-4949-a4fc-8a8ffb542797
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}