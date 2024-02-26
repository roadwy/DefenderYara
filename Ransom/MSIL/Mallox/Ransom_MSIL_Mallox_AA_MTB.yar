
rule Ransom_MSIL_Mallox_AA_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 34 00 30 00 } //01 00  http://80.66.75.40
		$a_01_1 = {52 00 65 00 66 00 6c 00 65 00 63 00 74 00 42 00 72 00 6f 00 61 00 64 00 63 00 61 00 73 00 74 00 65 00 72 00 } //01 00  ReflectBroadcaster
		$a_01_2 = {4c 6f 67 69 6e 46 61 63 74 6f 72 79 } //01 00  LoginFactory
		$a_01_3 = {52 65 76 65 72 74 46 61 63 74 6f 72 79 } //01 00  RevertFactory
		$a_01_4 = {41 77 61 6b 65 46 61 63 74 6f 72 79 } //01 00  AwakeFactory
		$a_01_5 = {43 6f 6d 70 75 74 65 50 72 6f 78 79 } //01 00  ComputeProxy
		$a_01_6 = {6a 73 6f 6e 57 72 69 74 65 72 } //00 00  jsonWriter
	condition:
		any of ($a_*)
 
}