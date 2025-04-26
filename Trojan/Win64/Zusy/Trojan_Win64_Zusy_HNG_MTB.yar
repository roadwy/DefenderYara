
rule Trojan_Win64_Zusy_HNG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 45 ?? 75 61 6c 50 c7 45 ?? 72 6f 74 65 66 c7 45 ?? 63 74 c6 45 de 00 c7 45 ?? 43 72 65 61 c7 45 ?? 74 65 54 68 c7 45 ?? 72 65 61 64 c6 45 cc 00 c7 45 ?? 57 61 69 74 c7 45 ?? 46 6f 72 53 c7 45 ?? 69 6e 67 6c c7 45 ?? 65 4f 62 6a c7 45 ?? 65 63 74 00 ff } //5
		$a_01_1 = {66 0f 1f 44 00 00 80 31 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}