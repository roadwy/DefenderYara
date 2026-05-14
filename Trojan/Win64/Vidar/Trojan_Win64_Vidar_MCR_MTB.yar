
rule Trojan_Win64_Vidar_MCR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 f0 53 00 2c f0 53 00 30 f0 53 00 20 e1 53 00 3c f0 53 00 00 00 61 2e 6f 75 74 2e 65 78 65 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 } //1
		$a_03_1 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a 08 02 [0-15] 06 67 6f 31 2e 32 30 d6 01 30 77 af 0c 92 74 08 02 41 e1 c1 07 e6 d6 18 e6 70 61 74 68 09 63 6f 6d 6d 61 6e 64 2d 6c 69 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}