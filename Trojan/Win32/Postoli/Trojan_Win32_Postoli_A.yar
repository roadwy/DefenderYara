
rule Trojan_Win32_Postoli_A{
	meta:
		description = "Trojan:Win32/Postoli.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 3f 00 75 00 70 00 64 00 61 00 74 00 65 00 3d 00 64 00 61 00 69 00 6c 00 79 00 26 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 3d 00 00 00 00 00 } //1
		$a_01_1 = {00 53 76 63 68 6f 73 74 2d 57 69 6e 64 6f 77 73 2d 52 65 64 71 75 69 72 65 64 00 00 } //1
		$a_01_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //1 \Microsoft\Windows\System\Hidden
		$a_01_3 = {53 79 73 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}