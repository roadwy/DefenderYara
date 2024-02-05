
rule Adware_AndroidOS_Mobidash_N_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 00 3d 00 71 10 90 01 02 03 00 1a 00 90 01 02 6e 20 90 01 02 03 00 0c 01 6e 10 90 01 02 01 00 6e 10 90 01 02 01 00 0c 01 6e 10 90 01 02 03 00 0c 03 6e 20 90 01 02 03 00 0c 03 22 00 90 01 02 70 20 90 01 02 10 00 70 30 90 01 02 32 00 28 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}