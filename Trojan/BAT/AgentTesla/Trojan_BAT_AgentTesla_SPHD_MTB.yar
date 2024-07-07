
rule Trojan_BAT_AgentTesla_SPHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 16 09 16 1e 28 90 01 03 0a 00 07 09 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 6f 90 01 03 0a 03 16 03 8e 90 00 } //1
		$a_01_1 = {4d 4f 41 4e 4d 5a 41 41 41 41 41 41 41 52 35 35 35 } //1 MOANMZAAAAAAAR555
		$a_01_2 = {43 41 53 4c 4c 4c 4c 4c 4c 4c } //1 CASLLLLLLL
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}