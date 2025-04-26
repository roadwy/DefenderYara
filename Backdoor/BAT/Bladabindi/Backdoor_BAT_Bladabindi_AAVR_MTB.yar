
rule Backdoor_BAT_Bladabindi_AAVR_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AAVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 20 f9 00 00 00 20 af 00 00 00 28 29 00 00 06 02 16 02 8e b7 6f ?? 00 00 0a 0a de 6e de 45 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}