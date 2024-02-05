
rule Trojan_BAT_AgentTesla_NRA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 60 00 00 5d 07 09 20 00 60 00 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d b7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NRA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {d0 00 b8 00 b8 00 b8 00 e2 00 b9 00 a7 00 b8 00 b8 00 b8 00 b8 00 ea 00 b8 00 b8 00 b8 00 b8 00 ee 00 ba 00 b8 00 b8 00 b8 00 b8 00 e0 00 } //01 00 
		$a_01_1 = {b8 00 ee 00 be 00 b8 00 e7 00 b9 00 de 00 c9 00 b8 00 c0 00 bf 00 b8 00 df 00 b9 00 de 00 cd 00 b8 00 bc 00 b8 00 b8 00 b8 00 b8 00 b8 00 c9 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 } //01 00 
		$a_01_2 = {d9 00 c0 00 c5 00 e5 00 b8 00 eb 00 b8 00 ab 00 de 00 ec 00 dd 00 ab 00 b8 00 b8 00 b8 00 b8 00 b8 00 de 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 b8 00 } //01 00 
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_4 = {77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 } //01 00 
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  01 00 
		$a_80_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  00 00 
	condition:
		any of ($a_*)
 
}