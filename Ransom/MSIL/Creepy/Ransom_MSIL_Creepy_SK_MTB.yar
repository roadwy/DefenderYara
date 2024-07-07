
rule Ransom_MSIL_Creepy_SK_MTB{
	meta:
		description = "Ransom:MSIL/Creepy.SK!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 65 70 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //5 Creepy Ransomware
		$a_01_1 = {67 65 74 5f 63 72 70 6b 65 79 } //1 get_crpkey
		$a_01_2 = {73 65 74 5f 63 72 70 6b 65 79 } //1 set_crpkey
		$a_01_3 = {49 74 73 20 61 20 70 6f 77 65 72 66 75 6c 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 Its a powerful ransomware
		$a_01_4 = {45 63 6e 72 79 70 74 65 64 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Ecnrypted your files
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}