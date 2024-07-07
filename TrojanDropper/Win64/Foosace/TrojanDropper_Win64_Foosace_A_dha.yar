
rule TrojanDropper_Win64_Foosace_A_dha{
	meta:
		description = "TrojanDropper:Win64/Foosace.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 1e 41 8a 34 19 8a c2 ff c2 41 f6 e9 41 02 c2 40 32 f0 41 88 34 19 44 8a 14 0a 45 84 d2 75 e6 } //1
		$a_00_1 = {66 69 6c 65 78 6f 72 00 } //1 楦敬潸r
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}