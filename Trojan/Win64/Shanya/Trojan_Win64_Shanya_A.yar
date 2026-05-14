
rule Trojan_Win64_Shanya_A{
	meta:
		description = "Trojan:Win64/Shanya.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 6d 73 67 61 70 69 2e 57 6d 73 67 42 72 6f 61 64 63 61 73 74 4d 65 73 73 61 67 65 00 } //1
		$a_03_1 = {0f be c8 81 c1 ?? ?? ?? ?? 45 6b c0 1f 48 ff c2 8a 02 44 33 c1 } //1
		$a_01_2 = {9c 66 81 0c 24 00 01 9d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}