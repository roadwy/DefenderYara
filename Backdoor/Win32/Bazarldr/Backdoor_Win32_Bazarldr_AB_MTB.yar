
rule Backdoor_Win32_Bazarldr_AB_MTB{
	meta:
		description = "Backdoor:Win32/Bazarldr.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 90 01 01 8a 1c 28 8a 14 0a 32 da 88 90 01 01 28 8b 44 24 1c 45 90 00 } //1
		$a_00_1 = {43 4c 53 49 44 5c 25 31 5c 4c 6f 63 61 6c 53 65 72 76 65 72 33 32 } //1 CLSID\%1\LocalServer32
		$a_00_2 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 } //1 Microsoft Visual C++ Runtime
		$a_00_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //1 VirtualAllocExNuma
		$a_00_4 = {41 6c 6c 20 66 69 6c 65 73 20 28 2a 2e 2a 29 7c 2a 2e 2a 7c 7c } //1 All files (*.*)|*.*||
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}