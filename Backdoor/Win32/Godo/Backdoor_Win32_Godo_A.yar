
rule Backdoor_Win32_Godo_A{
	meta:
		description = "Backdoor:Win32/Godo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2f 73 65 63 75 72 65 2f 75 70 64 61 74 65 90 03 06 05 73 74 61 74 75 73 63 68 65 63 6b 2e 68 74 6d 6c 3f 69 64 3d 25 73 26 90 00 } //1
		$a_01_1 = {64 6f 63 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 76 69 65 77 65 72 3f 75 72 6c 3d 25 73 26 65 6d 62 65 64 64 65 64 3d 74 72 75 65 } //1 docs.google.com/viewer?url=%s&embedded=true
		$a_01_2 = {41 6e 73 77 65 72 20 66 6f 72 20 63 6f 6d 6d 61 6e 64 20 5b } //1 Answer for command [
		$a_01_3 = {c7 06 0d 00 00 00 e8 4a 73 ff ff 83 7c 24 10 06 0f 85 d8 00 00 00 83 7c 24 14 02 75 2a 38 9c 24 a6 00 00 00 0f 85 2b 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}