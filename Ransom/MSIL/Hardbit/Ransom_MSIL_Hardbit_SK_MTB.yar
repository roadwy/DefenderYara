
rule Ransom_MSIL_Hardbit_SK_MTB{
	meta:
		description = "Ransom:MSIL/Hardbit.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {56 54 74 66 76 68 4a 46 73 56 54 74 66 4a 46 73 56 54 74 66 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  VTtfvhJFsVTtfJFsVTtf.Resources.resources
		$a_81_1 = {56 54 74 66 76 68 4a 46 73 56 54 74 66 4a 46 73 56 54 74 66 68 69 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  VTtfvhJFsVTtfJFsVTtfhid.Resources.resources
		$a_81_2 = {24 35 34 30 63 34 64 33 38 2d 37 66 66 38 2d 34 38 35 31 2d 62 63 62 37 2d 63 61 34 39 36 30 34 63 62 34 32 38 } //00 00  $540c4d38-7ff8-4851-bcb7-ca49604cb428
	condition:
		any of ($a_*)
 
}