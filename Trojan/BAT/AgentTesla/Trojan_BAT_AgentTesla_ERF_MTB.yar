
rule Trojan_BAT_AgentTesla_ERF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {0d 59 8e 7f 3d 4e 8e 7f 0d 59 8e 7f 0d 59 36 52 0d 59 } //1
		$a_01_1 = {41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e 53 69 64 } //1 AccountDomainSid
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {59 41 53 55 53 55 41 48 42 4e 5f 39 32 35 } //1 YASUSUAHBN_925
		$a_01_4 = {59 41 53 55 53 55 41 48 42 4e 5f 39 32 37 } //1 YASUSUAHBN_927
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}