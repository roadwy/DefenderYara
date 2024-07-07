
rule Trojan_Win32_PTASpy_A{
	meta:
		description = "Trojan:Win32/PTASpy.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 54 41 53 70 79 5c 50 54 41 53 70 79 2e 63 73 76 } //5 \PTASpy\PTASpy.csv
		$a_01_1 = {4c 6f 67 6f 6e 55 73 65 72 57 } //1 LogonUserW
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_4 = {43 72 79 70 74 42 69 6e 61 72 79 54 6f 53 74 72 69 6e 67 57 } //1 CryptBinaryToStringW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}