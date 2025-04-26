
rule Trojan_BAT_AgentTesla_EOZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 29 f5 8b 24 bd 3c 85 fa 1b 91 e1 d1 0c c2 4a f1 48 48 fb 8c 47 42 3d 0e 5b 00 2f 23 8b 94 1a 6f 77 08 b2 32 43 d1 4c a2 cb 5d 0f 47 89 c3 94 } //1
		$a_01_1 = {06 ee d1 bb 9f cb 4f bf dc a9 7b 8a dc 34 98 49 75 a1 9f b2 db 48 04 a5 0c b2 41 df 0b ed 8d 97 4e 37 25 d6 2d 44 71 46 15 40 31 4b a1 39 6b b9 } //1
		$a_01_2 = {55 4a 4a 45 c7 49 34 4b 5a 3c 27 b8 48 de b3 5d c5 aa c8 2a ba d7 55 4a 4a 45 c7 49 34 4b 5a 3c 27 b8 48 de b3 5d c5 aa c8 2a ba d7 55 4a 4a 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}