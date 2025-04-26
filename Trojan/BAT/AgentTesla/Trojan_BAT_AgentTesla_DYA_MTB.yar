
rule Trojan_BAT_AgentTesla_DYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {e0 47 5d f0 cb 5c a0 8f 3f d3 05 bf 7b e5 fd 3e 17 fc 51 17 fc d1 17 fc 29 17 7c 8b 0b fe a4 0b be e3 05 7f e2 05 df e1 ed f7 1f 72 c1 1f 7f 81 } //1
		$a_01_1 = {f1 bd 49 4f fa 51 af 79 d6 0f 7d 67 1b c9 a3 37 f6 12 19 b5 1c ec bd 5f 95 1e 90 be 7a 7f 96 7c fb 7d 57 f5 f9 ee d6 17 c7 c5 8e ec 93 e3 41 9f } //1
		$a_01_2 = {6b 23 f1 64 f9 07 e8 2a f7 ce 53 e3 a0 dd 7b 29 c1 f1 5b fb da f2 3b fc 37 e0 25 75 f2 74 e6 a5 4f be 0b 93 3b 68 d6 a3 ce b3 72 a7 db 19 da 7b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}