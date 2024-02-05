
rule Trojan_BAT_AgentTesla_DVV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 ee d9 f6 98 ff ea 89 3c f1 33 ad 87 6e 47 b1 bb b4 97 2e 77 f8 44 de c8 7f 04 47 ed e5 56 f9 8e fc 7a f4 13 fa d4 5f e2 93 3e ff 4d 74 e5 67 } //01 00 
		$a_01_1 = {5d d2 d3 e7 5c 80 df 67 59 90 34 ca 92 77 40 ce 19 9e f0 a5 17 fc da c2 29 f7 0c bf 7b 85 c1 b4 bb 4e ff 19 c7 7b db 77 c3 55 7c 40 19 f3 7e 46 } //00 00 
	condition:
		any of ($a_*)
 
}