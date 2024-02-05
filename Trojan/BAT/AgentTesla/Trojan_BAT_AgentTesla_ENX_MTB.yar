
rule Trojan_BAT_AgentTesla_ENX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 db f7 5d 8f be a2 e4 f9 ab e2 bd 4c b8 05 a7 77 ed f3 d5 09 3b c8 52 50 e0 b8 69 45 b2 d5 ab e2 bd 2c b8 57 ff ba 08 32 d7 d6 6e c6 f5 3f db } //01 00 
		$a_01_1 = {1c 11 2e 48 99 d3 b5 d4 f7 ea 86 5b 40 7e 96 b9 93 11 26 79 46 05 fc d5 10 4b 40 b2 da bc f5 5a 55 ec 97 0a 59 2d 3f a6 2f 59 2f e6 8a 35 53 85 } //01 00 
		$a_01_2 = {4c b8 f5 da 47 28 2f c6 de 32 36 51 3f d5 d2 4b 45 b2 d5 ab e2 bd 4c b8 f5 da 47 28 2f c6 de 32 36 51 3f d5 d2 4b 45 b2 d5 ab e2 bd 4c b8 f5 da } //00 00 
	condition:
		any of ($a_*)
 
}