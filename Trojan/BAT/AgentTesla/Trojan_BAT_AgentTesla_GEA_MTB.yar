
rule Trojan_BAT_AgentTesla_GEA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 70 77 65 72 59 65 76 65 6e 74 73 } //1 aspwerYevents
		$a_01_1 = {72 63 69 6d 6c 6d 5a 72 75 6b 67 4d 67 72 } //1 rcimlmZrukgMgr
		$a_01_2 = {73 66 6d 73 79 73 74 65 6d 59 53 67 34 30 30 } //1 sfmsystemYSg400
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //1 GetCurrentDirectory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}