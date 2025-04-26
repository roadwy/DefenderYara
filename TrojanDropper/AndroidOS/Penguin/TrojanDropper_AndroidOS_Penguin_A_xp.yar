
rule TrojanDropper_AndroidOS_Penguin_A_xp{
	meta:
		description = "TrojanDropper:AndroidOS/Penguin.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 68 31 1c 9b 69 98 47 06 1e 07 d1 2b 68 28 1c 5b 6c 98 47 26 60 66 60 30 1c } //1
		$a_00_1 = {39 1c 01 9a 08 9b ff f7 af ff 07 1e 07 d1 2b 68 28 1c 5b 6c 98 47 27 60 67 60 38 1c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}