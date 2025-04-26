
rule Adware_AndroidOS_MobiDash_AA_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.AA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {30 4a 30 4b 20 1c 31 1c 7a 44 7b 44 ff f7 07 fd 04 90 20 1c ff f7 2c fd 00 28 d6 d1 2b 4a 2b 4b 20 1c 31 1c 7a 44 7b 44 ff f7 f9 fc 05 90 20 1c ff f7 1e fd 00 28 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}