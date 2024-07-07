
rule Trojan_Win64_Sirefef_W{
	meta:
		description = "Trojan:Win64/Sirefef.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 47 4e 4f 4c 31 06 d1 c0 48 83 c6 04 83 90 01 01 ff 75 f3 90 00 } //1
		$a_03_1 = {48 8b 49 28 48 8d 15 90 01 04 41 b8 4d 00 00 00 48 83 c1 0c e8 90 00 } //1
		$a_00_2 = {38 00 31 00 44 00 30 00 35 00 46 00 39 00 41 00 2d 00 35 00 32 00 38 00 38 00 2d 00 } //1 81D05F9A-5288-
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_W_2{
	meta:
		description = "Trojan:Win64/Sirefef.W,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 47 4e 4f 4c 31 06 d1 c0 48 83 c6 04 83 90 01 01 ff 75 f3 90 00 } //1
		$a_03_1 = {48 8b 49 28 48 8d 15 90 01 04 41 b8 4d 00 00 00 48 83 c1 0c e8 90 00 } //1
		$a_00_2 = {38 00 31 00 44 00 30 00 35 00 46 00 39 00 41 00 2d 00 35 00 32 00 38 00 38 00 2d 00 } //1 81D05F9A-5288-
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}