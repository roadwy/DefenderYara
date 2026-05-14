
rule Trojan_BAT_Zusy_MCQ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 63 33 64 65 30 34 31 2d 62 35 32 65 2d 34 63 66 30 2d 38 62 65 30 2d 33 38 63 35 30 34 62 66 65 31 36 35 } //1 4c3de041-b52e-4cf0-8be0-38c504bfe165
		$a_01_1 = {63 6c 74 2e 65 78 65 00 63 6c 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}