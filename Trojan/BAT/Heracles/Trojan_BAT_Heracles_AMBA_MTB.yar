
rule Trojan_BAT_Heracles_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 16 9a 26 16 2d f9 00 28 90 01 01 00 00 06 72 90 01 02 00 70 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 0b 07 74 90 01 01 00 00 1b 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Heracles_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 14 0b 38 90 01 01 00 00 00 00 28 90 01 01 00 00 06 0b dd 90 01 01 00 00 00 26 dd 90 01 01 00 00 00 07 2c eb 07 8e 69 8d 90 01 01 00 00 01 0c 16 0d 38 90 01 01 00 00 00 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed 08 2a 90 00 } //5
		$a_01_1 = {4c 6f 61 64 00 47 65 74 54 79 70 65 00 47 65 74 4d 65 74 68 6f 64 00 54 6f 49 6e 74 33 32 } //5 潌摡䜀瑥祔数䜀瑥敍桴摯吀䥯瑮㈳
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_BAT_Heracles_AMBA_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 03 2d 18 07 06 28 90 01 01 00 00 0a 72 90 01 02 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2b 16 07 06 28 90 01 01 00 00 0a 72 90 01 02 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0d 09 02 16 02 8e 69 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a de 0a 90 00 } //1
		$a_03_1 = {0a 0a 06 02 6f 90 01 01 00 00 0a 06 03 6f 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 17 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}