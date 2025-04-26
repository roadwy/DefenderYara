
rule Trojan_Win32_CryptInject_DD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 ee 33 c5 33 44 24 10 68 b9 79 37 9e 8d 54 24 20 52 2b f8 } //1
		$a_01_1 = {81 ff ee 75 37 00 7f 09 47 81 ff f6 ea 2b 33 7c 87 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}