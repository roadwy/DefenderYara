
rule Trojan_Win64_IcedID_C_MTB{
	meta:
		description = "Trojan:Win64/IcedID.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 6c 71 65 64 36 2e 64 6c 6c } //1 jlqed6.dll
		$a_01_1 = {43 51 58 70 48 31 45 33 56 62 6b 76 45 59 4f 7a 54 4e 32 76 } //1 CQXpH1E3VbkvEYOzTN2v
		$a_01_2 = {43 7a 33 67 30 79 75 4a 4c 58 39 42 31 78 55 50 39 41 56 4b } //1 Cz3g0yuJLX9B1xUP9AVK
		$a_01_3 = {47 49 48 67 62 6a 68 61 73 64 76 67 76 61 73 64 68 6a 6b 61 6a } //1 GIHgbjhasdvgvasdhjkaj
		$a_01_4 = {4a 37 5a 4c 68 35 75 61 36 7a 4a 35 50 56 33 51 } //1 J7ZLh5ua6zJ5PV3Q
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}