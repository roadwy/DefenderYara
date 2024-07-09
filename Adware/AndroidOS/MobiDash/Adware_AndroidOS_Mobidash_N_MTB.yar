
rule Adware_AndroidOS_Mobidash_N_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 00 3d 00 71 10 ?? ?? 03 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00 0c 01 6e 10 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 01 6e 10 ?? ?? 03 00 0c 03 6e 20 ?? ?? 03 00 0c 03 22 00 ?? ?? 70 20 ?? ?? 10 00 70 30 ?? ?? 32 00 28 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}