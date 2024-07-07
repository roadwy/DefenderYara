
rule Trojan_BAT_AveMaria_NEDP_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 37 38 61 37 34 35 33 2d 30 32 61 39 2d 34 32 62 62 2d 38 64 35 61 2d 63 34 33 36 37 36 35 61 35 31 39 34 } //5 e78a7453-02a9-42bb-8d5a-c436765a5194
		$a_01_1 = {45 66 67 71 74 62 72 65 2e 65 78 65 } //5 Efgqtbre.exe
		$a_01_2 = {53 6d 61 72 74 20 49 6e 73 74 61 6c 6c 20 4d 61 6b 65 72 20 35 2e 30 32 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e } //3 Smart Install Maker 5.02 Installation
		$a_01_3 = {35 2e 32 2e 30 2e 30 } //2 5.2.0.0
		$a_01_4 = {53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 } //1 System.Collections.Generic
		$a_01_5 = {43 6f 6e 66 75 73 65 72 20 76 31 2e 39 2e 30 2e 30 } //1 Confuser v1.9.0.0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=17
 
}