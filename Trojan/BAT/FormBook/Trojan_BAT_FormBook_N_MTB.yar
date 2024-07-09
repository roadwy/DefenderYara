
rule Trojan_BAT_FormBook_N_MTB{
	meta:
		description = "Trojan:BAT/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 08 06 91 11 05 06 11 05 6f 63 01 00 0a 5d 6f 93 01 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_FormBook_N_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 61 32 35 36 30 65 66 38 2d 62 37 64 66 2d 34 37 61 65 2d 61 66 39 37 2d 34 39 35 34 37 35 31 66 64 32 33 32 } //1 $a2560ef8-b7df-47ae-af97-4954751fd232
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_FormBook_N_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 29 01 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 00 38 ?? ?? 00 00 72 ?? ?? 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 00 38 ?? ?? 00 00 72 ?? ?? 00 70 02 03 28 ?? ?? 00 06 0c 12 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a } //5
		$a_01_1 = {43 6f 6c 6c 69 73 69 6f 6e 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CollisionSimulation.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}