
rule Trojan_BAT_AgentTesla_RSI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 5f a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6d 00 00 00 14 00 00 00 38 00 00 00 86 00 00 00 67 00 00 00 04 00 00 00 c0 00 00 00 07 00 00 00 3b 00 00 00 01 00 00 00 1b 00 00 00 07 00 00 00 14 00 00 00 23 00 00 00 09 00 00 00 01 00 00 00 06 00 00 00 02 00 00 00 02 } //1
		$a_81_1 = {61 33 64 35 32 61 30 33 2d 39 37 65 36 2d 34 64 62 31 2d 61 62 31 62 2d 62 38 39 39 36 62 36 31 39 36 38 65 } //1 a3d52a03-97e6-4db1-ab1b-b8996b61968e
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}