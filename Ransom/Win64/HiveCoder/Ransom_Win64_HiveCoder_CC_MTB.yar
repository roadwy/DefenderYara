
rule Ransom_Win64_HiveCoder_CC_MTB{
	meta:
		description = "Ransom:Win64/HiveCoder.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {21 65 72 72 6f 72 3a 20 6e 6f 20 66 6c 61 67 20 2d 75 20 3c 6c 6f 67 69 6e 3e 3a 3c 70 61 73 73 77 6f 72 64 3e 20 70 72 6f 76 69 64 65 64 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 30 78 25 78 } //01 00 
		$a_01_2 = {2e 6b 65 79 } //01 00 
		$a_01_3 = {42 43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}