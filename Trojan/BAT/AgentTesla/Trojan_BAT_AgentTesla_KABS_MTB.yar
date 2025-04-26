
rule Trojan_BAT_AgentTesla_KABS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {41 75 6b 63 69 6f 6e 44 42 44 61 74 61 53 65 74 } //AukcionDBDataSet  1
		$a_80_1 = {44 42 5f 6b 75 72 73 77 6f 72 6b } //DB_kurswork  1
		$a_80_2 = {74 65 6d 70 75 72 69 } //tempuri  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}