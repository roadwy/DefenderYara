
rule Trojan_Win32_Bamital_gen_H{
	meta:
		description = "Trojan:Win32/Bamital.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 8b f8 8b f0 03 75 0c 03 7d 10 53 57 56 ff 75 08 e8 19 ff ff ff 5f 59 83 c7 28 e2 a3 c9 } //1
		$a_03_1 = {89 01 c7 41 04 2e 64 61 74 c7 41 08 00 00 00 00 8d 45 90 01 01 50 ff 75 08 e8 90 01 04 89 45 e0 90 00 } //1
		$a_03_2 = {83 3c 03 00 75 16 c7 04 03 01 00 00 00 8d 0d 90 01 04 83 c1 04 03 cb 8b c1 ff d1 61 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}