
rule Backdoor_BAT_LimeRat_AY_MTB{
	meta:
		description = "Backdoor:BAT/LimeRat.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 0a 1f 28 8d 02 00 00 01 25 d0 01 00 00 04 28 02 00 00 0a 6f 03 00 00 0a 0a 28 01 00 00 0a 1f 28 8d 02 00 00 01 25 } //2
		$a_03_1 = {0a 1f 28 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 1f 28 8d ?? 00 00 01 25 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //2 TransformFinalBlock
		$a_01_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //2 SymmetricAlgorithm
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}