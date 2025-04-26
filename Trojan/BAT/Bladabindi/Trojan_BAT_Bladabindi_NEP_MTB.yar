
rule Trojan_BAT_Bladabindi_NEP_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 34 36 39 33 38 32 43 37 44 36 44 37 38 41 42 34 32 36 32 38 33 45 32 } //5 B469382C7D6D78AB426283E2
		$a_01_1 = {62 62 38 30 35 30 63 34 2d 35 35 38 63 2d 34 39 66 63 2d 39 34 36 64 2d 63 37 61 63 39 38 38 33 63 30 32 65 } //5 bb8050c4-558c-49fc-946d-c7ac9883c02e
		$a_01_2 = {78 00 69 00 6e 00 68 00 65 00 79 00 75 00 6e 00 2e 00 63 00 6f 00 6d 00 } //5 xinheyun.com
		$a_01_3 = {53 75 70 6d 65 61 45 7a 43 61 64 } //5 SupmeaEzCad
		$a_01_4 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e } //2 Newtonsoft.Json
		$a_01_5 = {6c 6d 63 31 5f 4d 61 72 6b 45 6e 74 69 74 79 46 6c 79 } //2 lmc1_MarkEntityFly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=24
 
}