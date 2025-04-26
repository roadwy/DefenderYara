
rule Trojan_BAT_AgentTesla_EOW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 59 55 2b 39 bd 30 42 34 37 dc ad c4 34 b7 c7 29 c4 9c df be bf 54 59 55 2b b9 bd b0 42 ca ea b6 2c 86 66 d0 a4 c1 61 5c 0d f0 14 2f f0 50 8e } //1
		$a_01_1 = {a3 f7 29 c4 16 27 9a b8 50 82 c3 7d 23 bd 30 42 35 cb 59 a9 80 a6 97 cb 14 86 f9 df be bf 57 47 16 b4 3d b1 8c 4f 9b 35 e5 ad c4 34 aa c1 ea 4b } //1
		$a_01_2 = {39 bd 30 42 34 37 dc ad c4 34 b7 c7 29 c4 9c df be bf 54 59 55 2b 39 bd 30 42 34 37 dc ad c4 34 b7 c7 29 c4 9c df be bf 54 59 55 2b 39 bd 30 42 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}