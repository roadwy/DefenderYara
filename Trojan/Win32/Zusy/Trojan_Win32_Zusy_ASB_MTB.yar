
rule Trojan_Win32_Zusy_ASB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f3 0f b6 44 15 00 30 04 0e 83 c1 01 39 cf 75 } //1
		$a_03_1 = {89 34 24 89 44 24 04 c7 45 ?? 66 75 63 6b c7 45 ?? 79 6f 75 00 e8 } //1
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 77 77 6d 6d 2e 74 78 74 } //1 C:\Users\Public\dwwmm.txt
		$a_01_3 = {2f 6d 31 2e 74 78 74 } //1 /m1.txt
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}