
rule Trojan_BAT_LummaStealer_ALM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 19 6c 11 1a 6c 5b 28 4b 00 00 0a b7 13 10 20 02 } //2
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6e 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 45 00 7a 00 69 00 72 00 69 00 7a 00 27 00 73 00 } //1 This assembly is protected by an unregistered version of Eziriz's
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_LummaStealer_ALM_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 46 59 53 56 59 7a 43 68 78 56 73 58 57 6d 52 73 59 71 75 2e 64 6c 6c } //1 oFYSVYzChxVsXWmRsYqu.dll
		$a_01_1 = {74 7a 59 73 6c 6b 45 45 78 42 7a 68 57 51 6a 59 41 54 48 4f 65 2e 64 6c 6c } //1 tzYslkEExBzhWQjYATHOe.dll
		$a_01_2 = {4f 64 5a 6f 6b 6f 4b 6c 4a 65 6e 76 44 62 68 54 67 2e 64 6c 6c } //1 OdZokoKlJenvDbhTg.dll
		$a_01_3 = {48 65 57 53 66 46 57 75 46 6d 6d 4d 45 51 79 2e 64 6c 6c } //1 HeWSfFWuFmmMEQy.dll
		$a_01_4 = {49 4c 4c 6e 6f 67 5a 79 5a 4c 55 74 56 58 69 4f 76 77 52 48 70 54 65 77 42 4e 73 2e 64 6c 6c } //1 ILLnogZyZLUtVXiOvwRHpTewBNs.dll
		$a_01_5 = {64 34 66 35 65 36 61 37 2d 62 38 63 39 2d 34 30 31 32 2d 38 61 33 34 2d 35 36 37 38 39 61 62 63 64 30 31 32 } //1 d4f5e6a7-b8c9-4012-8a34-56789abcd012
		$a_01_6 = {35 50 69 6f 6e 65 65 72 69 6e 67 20 74 65 63 68 6e 6f 6c 6f 67 79 20 73 6f 6c 75 74 69 6f 6e 73 20 66 6f 72 20 61 20 73 6d 61 72 74 65 72 20 66 75 74 75 72 65 } //1 5Pioneering technology solutions for a smarter future
		$a_01_7 = {51 00 75 00 61 00 6e 00 74 00 75 00 6d 00 57 00 61 00 76 00 65 00 20 00 49 00 6e 00 6e 00 6f 00 76 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 54 00 72 00 61 00 64 00 65 00 6d 00 61 00 72 00 6b 00 } //1 QuantumWave Innovations Trademark
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}