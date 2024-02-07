
rule Trojan_BAT_AgentTesla_EXR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 45 41 39 35 34 42 35 36 2d 42 38 39 34 2d 34 45 41 36 2d 41 43 42 34 2d 42 43 31 38 38 36 44 46 42 44 37 34 } //0a 00  $EA954B56-B894-4EA6-ACB4-BC1886DFBD74
		$a_01_1 = {24 30 32 43 35 32 41 31 36 2d 42 32 34 32 2d 34 39 39 30 2d 41 46 32 33 2d 46 33 45 35 37 34 46 43 32 31 37 42 } //01 00  $02C52A16-B242-4990-AF23-F3E574FC217B
		$a_01_2 = {45 67 72 61 2e 64 6c 6c } //01 00  Egra.dll
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_4 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_5 = {00 47 65 74 4d 65 74 68 6f 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}