
rule Trojan_BAT_Rozena_PSJS_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 73 75 66 77 34 65 76 } //01 00  hsufw4ev
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_3 = {65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  explore.exe
		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_5 = {7c 6d 79 73 65 6c 66 2e 64 6c 6c } //00 00  |myself.dll
	condition:
		any of ($a_*)
 
}