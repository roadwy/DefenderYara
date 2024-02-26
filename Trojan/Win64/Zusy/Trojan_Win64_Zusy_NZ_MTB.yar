
rule Trojan_Win64_Zusy_NZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 75 73 20 4c 6f 61 64 65 72 2e 70 64 62 } //01 00  Hus Loader.pdb
		$a_01_1 = {4b 65 79 20 64 6f 65 73 6e 74 20 65 78 69 73 74 20 21 } //01 00  Key doesnt exist !
		$a_01_2 = {64 73 63 2e 67 67 2f 72 69 76 65 } //01 00  dsc.gg/rive
		$a_01_3 = {48 75 73 43 6c 61 73 73 } //00 00  HusClass
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 63 6d 64 20 2f 43 } //01 00  start cmd /C
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_3 = {56 65 72 69 53 69 67 6e 4d 50 4b 49 2d 32 2d 33 39 35 30 } //01 00  VeriSignMPKI-2-3950
		$a_01_4 = {4f 52 5f 31 50 34 52 50 34 31 } //00 00  OR_1P4RP41
	condition:
		any of ($a_*)
 
}