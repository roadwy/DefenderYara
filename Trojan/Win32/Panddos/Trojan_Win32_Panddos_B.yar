
rule Trojan_Win32_Panddos_B{
	meta:
		description = "Trojan:Win32/Panddos.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {57 49 4e 5f 32 30 30 33 90 02 0f 64 72 65 61 6d 32 66 6c 79 90 00 } //1
		$a_01_1 = {64 65 78 20 52 65 61 64 43 6c 69 65 6e 74 43 66 67 20 2e 2e 00 52 65 76 65 72 73 65 53 68 65 6c 6c 20 73 74 61 72 74 2e 2e 00 00 00 00 42 69 6e 64 53 68 65 6c 6c 20 6c 65 61 76 65 } //1
		$a_01_2 = {77 65 6c 63 6f 6d 65 20 74 6f 20 73 6d 61 72 74 64 6f 6f 72 20 63 6d 64 20 73 68 65 6c 6c 2e } //1 welcome to smartdoor cmd shell.
		$a_01_3 = {4c 6f 67 69 6e 20 73 75 63 63 65 73 73 21 4e 6f 77 2c 20 79 6f 75 20 68 61 76 65 20 61 20 73 79 73 74 65 6d 20 63 6d 64 20 73 68 65 6c 6c 5e 5f 5e 41 20 5a 41 2c 41 20 5a 41 2c 41 20 5a 41 21 } //1 Login success!Now, you have a system cmd shell^_^A ZA,A ZA,A ZA!
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}