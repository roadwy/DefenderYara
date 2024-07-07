
rule Trojan_BAT_AgentTesla_K_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 28 90 01 03 06 9d 25 17 28 90 01 03 06 9d 25 18 28 90 01 03 06 9d 25 19 28 90 01 03 06 9d 73 90 01 03 0a 80 90 01 03 04 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_K_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.K!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 00 6c 00 65 00 6e 00 64 00 43 00 6f 00 72 00 65 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 BlendCore.Resources
		$a_01_1 = {52 00 61 00 74 00 52 00 75 00 6e 00 50 00 63 00 74 00 } //1 RatRunPct
		$a_01_2 = {52 00 61 00 74 00 50 00 63 00 74 00 } //1 RatPct
		$a_01_3 = {52 00 61 00 74 00 52 00 75 00 6e 00 } //1 RatRun
		$a_01_4 = {52 00 61 00 74 00 52 00 75 00 6e 00 35 00 } //1 RatRun5
		$a_01_5 = {42 00 61 00 63 00 6b 00 52 00 61 00 74 00 } //1 BackRat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}