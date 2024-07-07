
rule Backdoor_Win32_Bustem_A{
	meta:
		description = "Backdoor:Win32/Bustem.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 61 72 61 6d 73 22 3a 5b 5d 2c 22 6d 65 74 68 6f 64 22 3a 22 67 65 74 77 6f 72 6b 22 2c 22 69 64 22 3a 22 6a 73 6f 6e } //1 params":[],"method":"getwork","id":"json
		$a_01_1 = {73 6f 63 6b 20 63 72 65 61 74 65 64 3a 20 25 64 20 28 25 64 3a 25 64 3a 25 64 29 } //1 sock created: %d (%d:%d:%d)
		$a_01_2 = {75 73 65 72 3a 70 61 73 73 77 6f 72 64 } //1 user:password
		$a_01_3 = {31 30 39 2e 32 33 30 2e 32 34 36 2e 36 36 } //1 109.230.246.66
		$a_01_4 = {31 30 39 2e 32 33 30 2e 32 31 37 2e 31 33 } //1 109.230.217.13
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}