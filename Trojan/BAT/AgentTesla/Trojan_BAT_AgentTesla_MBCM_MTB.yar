
rule Trojan_BAT_AgentTesla_MBCM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 ?? 00 00 06 13 02 38 ?? 00 00 00 28 ?? 00 00 06 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 } //1
		$a_01_1 = {2f 00 63 00 61 00 72 00 6c 00 63 00 65 00 64 00 65 00 72 00 6c 00 61 00 77 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 /carlcederlaw.com/
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}