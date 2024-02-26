
rule Trojan_Win64_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 72 69 74 65 72 66 75 6e 63 74 69 6f 6e 70 72 6f 2e 65 78 65 } //01 00  writerfunctionpro.exe
		$a_01_1 = {74 69 6d 65 70 72 6f 67 72 61 6d 6d 65 72 2e 65 78 65 } //01 00  timeprogrammer.exe
		$a_01_2 = {53 00 65 00 6e 00 64 00 45 00 66 00 66 00 65 00 63 00 74 00 69 00 76 00 65 00 6c 00 79 00 } //01 00  SendEffectively
		$a_01_3 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //01 00  DecryptFileA
		$a_01_4 = {44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //00 00  DelNodeRunDLL32
	condition:
		any of ($a_*)
 
}