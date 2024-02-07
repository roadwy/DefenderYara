
rule Trojan_BAT_AgentTesla_RPU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 } //01 00  example.com
		$a_01_1 = {54 00 74 00 7a 00 79 00 7a 00 61 00 74 00 2e 00 70 00 6e 00 67 00 } //01 00  Ttzyzat.png
		$a_01_2 = {4d 00 6d 00 61 00 79 00 71 00 78 00 73 00 74 00 65 00 6d 00 77 00 61 00 } //01 00  Mmayqxstemwa
		$a_01_3 = {57 00 6f 00 68 00 68 00 73 00 68 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 } //01 00  Wohhshm.Properties
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_6 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {34 00 30 00 34 00 30 00 30 00 38 00 36 00 35 00 34 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 30 00 39 00 38 00 37 00 36 00 35 00 34 00 32 00 32 00 2e 00 70 00 6e 00 67 00 } //01 00  4040086543456789098765422.png
		$a_01_2 = {59 00 6f 00 64 00 79 00 75 00 75 00 63 00 64 00 74 00 73 00 68 00 6e 00 71 00 66 00 66 00 78 00 67 00 6a 00 70 00 70 00 79 00 69 00 2e 00 58 00 75 00 70 00 6b 00 61 00 70 00 78 00 77 00 74 00 63 00 79 00 65 00 } //01 00  Yodyuucdtshnqffxgjppyi.Xupkapxwtcye
		$a_01_3 = {42 00 70 00 6a 00 61 00 6b 00 71 00 6d 00 6e 00 } //01 00  Bpjakqmn
		$a_01_4 = {45 00 6d 00 61 00 69 00 6c 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 20 00 50 00 72 00 6f 00 } //00 00  Email Checker Pro
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPU_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 1b 0a 2b db 7d 01 00 00 04 2b e7 0b 2b f1 20 d0 07 00 00 38 aa 00 00 00 07 17 58 0b 07 1b fe 04 0c 08 2c 03 17 2b 03 16 2b 00 2d e2 } //00 00 
	condition:
		any of ($a_*)
 
}