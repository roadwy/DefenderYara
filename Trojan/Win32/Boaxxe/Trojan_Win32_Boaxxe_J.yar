
rule Trojan_Win32_Boaxxe_J{
	meta:
		description = "Trojan:Win32/Boaxxe.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {7d 07 00 00 76 05 83 c8 ff eb 38 } //1
		$a_03_1 = {00 95 01 00 00 73 07 b8 06 00 00 00 eb 18 81 90 01 04 00 2f 03 00 00 73 07 b8 02 00 00 00 eb 05 90 00 } //1
		$a_03_2 = {35 92 56 00 00 90 02 10 00 79 00 00 00 90 00 } //1
		$a_03_3 = {8b 4d ec 83 c1 01 89 4d ec 83 7d ec 65 7d 16 6a 03 e8 90 01 04 83 c4 04 6a 0c e8 90 01 04 83 c4 04 eb db 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}