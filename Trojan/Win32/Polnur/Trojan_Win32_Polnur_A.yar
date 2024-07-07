
rule Trojan_Win32_Polnur_A{
	meta:
		description = "Trojan:Win32/Polnur.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 6c 4d 61 74 72 69 78 53 74 6f 72 61 67 65 4d 61 6e 61 67 65 72 } //1 IntelMatrixStorageManager
		$a_01_1 = {69 61 61 6e 74 6d 6f 6e } //1 iaantmon
		$a_01_2 = {66 89 0f 48 5f 8d 64 24 00 8a 48 01 40 84 c9 75 f8 } //2
		$a_03_3 = {83 c4 18 4f 8a 47 01 47 84 c0 75 f8 b9 0c 00 00 00 be 90 01 03 00 f3 a5 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 66 a5 68 00 00 00 80 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*5) >=8
 
}