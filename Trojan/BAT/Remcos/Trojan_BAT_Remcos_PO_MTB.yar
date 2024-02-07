
rule Trojan_BAT_Remcos_PO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 66 63 37 35 32 65 38 35 2d 30 63 64 30 2d 34 33 31 37 2d 62 39 35 34 2d 66 37 35 34 30 36 38 66 30 66 63 34 } //14 00  $fc752e85-0cd0-4317-b954-f754068f0fc4
		$a_81_1 = {24 61 31 32 37 62 63 33 35 2d 30 65 32 39 2d 34 39 33 39 2d 62 30 33 62 2d 35 63 37 66 66 61 35 36 63 35 32 66 } //14 00  $a127bc35-0e29-4939-b03b-5c7ffa56c52f
		$a_81_2 = {24 61 64 62 35 32 62 62 66 2d 63 65 38 37 2d 34 39 38 64 2d 61 39 39 33 2d 34 33 66 61 37 38 61 35 63 64 36 33 } //01 00  $adb52bbf-ce87-498d-a993-43fa78a5cd63
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {43 61 72 64 73 5f 49 6e 74 65 72 66 61 63 65 73 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Cards_Interfaces.My.Resources
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {52 65 66 6c 65 63 74 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 73 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ReflectionExtensions.My.Resources
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {4d 69 6e 69 43 61 6c 63 2e 52 65 73 6f 75 72 63 65 73 } //01 00  MiniCalc.Resources
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}