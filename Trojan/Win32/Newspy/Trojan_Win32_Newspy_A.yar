
rule Trojan_Win32_Newspy_A{
	meta:
		description = "Trojan:Win32/Newspy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 0c 41 3a 5c 00 33 db 8d 4b 41 } //1
		$a_01_1 = {8b 55 f4 8a 14 11 f6 da 30 14 38 40 41 3b 45 f8 72 e8 } //1
		$a_01_2 = {25 73 20 25 73 20 62 75 69 6c 64 20 25 73 00 } //1
		$a_01_3 = {66 69 6c 65 6e 61 6d 65 3d 22 66 69 6c 65 2e 72 61 77 22 } //1 filename="file.raw"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}