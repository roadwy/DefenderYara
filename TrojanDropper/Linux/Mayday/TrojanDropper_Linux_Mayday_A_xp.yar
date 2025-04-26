
rule TrojanDropper_Linux_Mayday_A_xp{
	meta:
		description = "TrojanDropper:Linux/Mayday.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {b5 32 03 16 e3 72 5d 8a ff 47 94 bf b4 93 39 a8 52 97 2b 89 d3 0e fe 7b 0b 98 d9 37 b3 a5 be 89 97 53 e6 2e 0c 7e be 8d 67 a4 35 } //1
		$a_00_1 = {99 b8 15 2b 39 43 c1 6b 54 f1 03 d9 03 9c da f5 19 59 07 94 b2 69 7d a9 f5 1c 87 2d 30 e5 72 df } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}