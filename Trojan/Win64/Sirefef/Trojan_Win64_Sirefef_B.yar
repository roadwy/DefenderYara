
rule Trojan_Win64_Sirefef_B{
	meta:
		description = "Trojan:Win64/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 49 8b 90 01 01 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_03_1 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 90 09 10 00 00 24 00 00 90 00 } //1
		$a_01_2 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 49 6e 43 53 52 53 53 } //1 x64\release\InCSRSS
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_B_2{
	meta:
		description = "Trojan:Win64/Sirefef.B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 49 8b 90 01 01 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_03_1 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 90 09 10 00 00 24 00 00 90 00 } //1
		$a_01_2 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 49 6e 43 53 52 53 53 } //1 x64\release\InCSRSS
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}