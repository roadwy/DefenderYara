
rule Adware_AndroidOS_Adlo_A_MTB{
	meta:
		description = "Adware:AndroidOS/Adlo.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {1c 00 00 00 6e 10 ?? 01 01 00 0a 00 23 00 ?? 00 6e 20 ?? 01 01 00 6e 10 ?? 01 01 00 71 10 ?? 01 00 00 0c 01 6e 20 ?? 01 12 00 6e 10 ?? 01 02 00 } //10
		$a_03_1 = {12 00 00 00 21 ?? 23 00 ?? 00 12 01 [0-05] 35 [0-03] 00 48 [0-08] 8d ?? 4f ?? 00 ?? d8 [0-03] 01 } //10
		$a_00_2 = {63 72 65 61 74 65 4e 65 77 46 69 6c 65 } //1 createNewFile
		$a_00_3 = {42 61 73 65 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 BaseDexClassLoader
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}