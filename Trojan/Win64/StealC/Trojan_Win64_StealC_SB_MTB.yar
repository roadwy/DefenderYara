
rule Trojan_Win64_StealC_SB_MTB{
	meta:
		description = "Trojan:Win64/StealC.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 72 61 69 6e 4c 6f 67 } //1 DrainLog
		$a_81_1 = {44 75 6d 70 48 75 6e 67 50 72 6f 63 65 73 73 57 69 74 68 50 74 79 70 65 5f 45 78 70 6f 72 74 54 68 75 6e 6b } //1 DumpHungProcessWithPtype_ExportThunk
		$a_81_2 = {44 59 58 5a 6a 6c 65 62 4d } //1 DYXZjlebM
		$a_81_3 = {44 68 4f 6f 6a 6f 49 4f 41 67 71 32 4b 65 71 6c 4d 48 31 39 72 69 43 74 67 46 76 56 75 } //1 DhOojoIOAgq2KeqlMH19riCtgFvVu
		$a_81_4 = {44 69 73 61 62 6c 65 48 6f 6f 6b } //1 DisableHook
		$a_81_5 = {45 36 79 51 77 4c 33 50 56 4e 6c 44 39 64 32 70 54 6b 35 48 30 56 69 62 69 59 48 39 65 61 74 71 } //1 E6yQwL3PVNlD9d2pTk5H0VibiYH9eatq
		$a_81_6 = {45 49 67 58 72 4b 6f 75 } //1 EIgXrKou
		$a_81_7 = {45 6e 38 43 34 39 7a 43 75 4d 44 78 4f 49 65 72 6c } //1 En8C49zCuMDxOIerl
		$a_81_8 = {45 73 4f 35 6a 6d 4e 49 7a 54 35 6f 4e 49 4c 4c 4c 38 53 47 } //1 EsO5jmNIzT5oNILLL8SG
		$a_81_9 = {46 48 42 5a 4b 32 4a 43 } //1 FHBZK2JC
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}