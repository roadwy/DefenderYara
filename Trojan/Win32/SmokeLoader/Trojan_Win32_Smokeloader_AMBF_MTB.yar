
rule Trojan_Win32_Smokeloader_AMBF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {54 75 70 65 79 61 74 6f 7a 20 6b 61 6b 65 7a 75 66 6f 72 } //Tupeyatoz kakezufor  1
		$a_80_1 = {4a 65 68 65 73 20 70 75 63 65 64 61 79 75 72 69 6b 69 } //Jehes pucedayuriki  1
		$a_80_2 = {42 65 7a 65 6d 61 74 65 76 61 6e 65 72 69 20 66 65 64 69 6c 6f 76 65 77 65 } //Bezematevaneri fedilovewe  1
		$a_80_3 = {7a 69 68 6f 67 6f 66 61 78 65 78 6f 72 75 68 65 63 65 64 65 63 } //zihogofaxexoruhecedec  1
		$a_80_4 = {6b 61 68 6f 6b 69 76 65 7a 61 76 } //kahokivezav  1
		$a_80_5 = {77 69 6c 65 62 75 64 75 67 61 72 75 72 61 76 65 } //wilebudugarurave  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}