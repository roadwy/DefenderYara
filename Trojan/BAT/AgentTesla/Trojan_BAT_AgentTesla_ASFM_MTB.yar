
rule Trojan_BAT_AgentTesla_ASFM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 6a 5d d4 91 08 11 ?? 08 8e 69 6a 5d d4 91 61 07 11 ?? 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 [0-04] 07 8e 69 6a 5d d4 11 ?? 20 00 01 00 00 5d d2 9c } //1
		$a_01_1 = {4f 00 37 00 35 00 35 00 34 00 53 00 35 00 48 00 5a 00 34 00 44 00 52 00 44 00 50 00 38 00 4b 00 38 00 43 00 56 00 48 00 50 00 38 00 } //1 O7554S5HZ4DRDP8K8CVHP8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}