
rule Trojan_BAT_AgentTesla_RDZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 31 30 30 64 62 33 66 2d 34 37 66 65 2d 34 35 37 66 2d 61 63 64 62 2d 34 65 39 35 31 65 35 63 34 31 36 65 } //1 6100db3f-47fe-457f-acdb-4e951e5c416e
		$a_01_1 = {4d 49 53 20 4f 72 64 65 72 53 74 61 74 75 73 } //1 MIS OrderStatus
		$a_01_2 = {6c 6f 76 65 } //1 love
		$a_01_3 = {53 61 6c 69 64 61 } //1 Salida
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}