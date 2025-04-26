
rule Trojan_BAT_AgentTesla_EMN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {b6 c5 9f c3 b6 c5 9f c3 b6 c5 9f c3 b6 c5 9f 43 c3 b6 c5 9f c4 93 c3 b6 c5 9f c3 b6 c5 9f 77 c3 b6 c5 9f c3 b6 c5 9f c3 b6 c5 9f 43 77 4d 51 c3 } //1
		$a_01_1 = {c5 9f c3 b6 c5 9f c3 b6 c5 9f 4a 4d c3 b6 c5 9f 48 53 c3 b6 c5 9f 34 44 65 77 c3 b6 c5 9f 57 46 6b c3 b6 c5 9f c3 b6 c5 9f c3 b6 c5 9f c3 b6 c5 } //1
		$a_01_2 = {c5 9f 6e 4e 49 62 67 c4 93 54 4d 30 68 56 47 68 70 63 79 c4 93 77 63 6d 39 6e 63 6d 46 74 49 47 4e 68 62 6d 35 76 64 43 c4 93 69 5a 53 c4 93 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}