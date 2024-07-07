
rule Trojan_Win64_Sirefef_G{
	meta:
		description = "Trojan:Win64/Sirefef.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 49 8b 90 01 01 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {ff e0 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00 41 51 } //1
		$a_01_2 = {49 6e 43 53 52 53 53 2e 64 6c 6c 00 43 6f 6e 53 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_G_2{
	meta:
		description = "Trojan:Win64/Sirefef.G,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 49 8b 90 01 01 48 8b f8 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {ff e0 4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 64 64 72 65 73 73 00 41 51 } //1
		$a_01_2 = {49 6e 43 53 52 53 53 2e 64 6c 6c 00 43 6f 6e 53 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}