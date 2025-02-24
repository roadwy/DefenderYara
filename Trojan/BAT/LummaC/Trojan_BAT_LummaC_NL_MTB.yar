
rule Trojan_BAT_LummaC_NL_MTB{
	meta:
		description = "Trojan:BAT/LummaC.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 61 72 6b 20 73 65 72 76 69 63 65 20 65 78 70 6c 6f 72 65 } //3 dark service explore
		$a_01_1 = {64 65 73 74 72 6f 79 20 6f 6c 64 20 77 65 } //2 destroy old we
		$a_01_2 = {49 73 4c 6f 67 67 69 6e 67 } //2 IsLogging
		$a_01_3 = {65 6e 65 72 67 79 20 72 6f 75 67 68 20 73 74 61 72 } //1 energy rough star
		$a_01_4 = {24 35 64 66 61 38 37 35 35 2d 36 64 32 33 2d 34 64 36 31 2d 61 34 66 36 2d 36 61 33 66 32 66 34 32 63 34 34 33 } //1 $5dfa8755-6d23-4d61-a4f6-6a3f2f42c443
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}