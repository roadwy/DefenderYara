
rule Trojan_BAT_Injector_QWER_MTB{
	meta:
		description = "Trojan:BAT/Injector.QWER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4a 69 74 48 65 6c 70 65 72 73 2e 4d 73 33 64 4c 6f 61 64 65 72 } //01 00  JitHelpers.Ms3dLoader
		$a_81_1 = {52 65 73 75 6d 65 4c 61 79 6f 75 74 } //01 00  ResumeLayout
		$a_81_2 = {4d 75 74 65 78 43 72 65 61 74 6f 72 } //01 00  MutexCreator
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {59 6f 75 72 20 66 69 6c 65 20 77 61 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 63 6f 6e 76 65 72 74 65 64 } //00 00  Your file was successfully converted
	condition:
		any of ($a_*)
 
}