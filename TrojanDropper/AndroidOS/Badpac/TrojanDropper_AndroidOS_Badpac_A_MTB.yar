
rule TrojanDropper_AndroidOS_Badpac_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Badpac.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {05 1c 20 1c ff f7 f7 fc 29 1c 04 90 20 1c ff f7 f2 fc 3d 49 07 1c 20 1c 79 44 ff f7 75 fc 3b 4a 3b 4b 05 1c 29 1c 7b 44 7a 44 20 1c ff f7 af fc 29 1c 02 1c 20 1c ff f7 b1 fc 36 49 06 1c 20 1c 79 44 ff f7 61 fc 34 4a 34 4b 05 1c 29 1c 7a 44 7b 44 20 1c ff f7 79 fc 00 23 02 1c } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}