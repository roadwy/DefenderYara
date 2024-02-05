
rule TrojanDropper_AndroidOS_Rootnik_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Rootnik.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {3b 1c a8 47 35 1c 82 46 00 28 1a d1 84 23 99 46 0a e0 23 68 4a 46 20 1c 9e 58 29 1c 42 46 3b 1c b0 47 00 28 18 d1 2e 1c } //00 00 
	condition:
		any of ($a_*)
 
}