
rule Trojan_Win32_IcedID_GG_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 61 64 65 72 5f 64 6c 6c 5f 36 34 2e 64 6c 6c } //loader_dll_64.dll  10
		$a_80_1 = {61 77 73 2e 61 6d 61 7a 6f 6e 2e 63 6f 6d } //aws.amazon.com  1
		$a_80_2 = {43 6f 6f 6b 69 65 3a 20 5f 5f 67 61 64 73 3d } //Cookie: __gads=  1
		$a_80_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_4 = {3b 20 5f 67 61 74 3d } //; _gat=  1
		$a_80_5 = {3b 20 5f 67 61 3d } //; _ga=  1
		$a_80_6 = {3b 20 5f 75 3d } //; _u=  1
		$a_80_7 = {3b 20 5f 5f 69 6f 3d } //; __io=  1
		$a_80_8 = {3b 20 5f 67 69 64 3d } //; _gid=  1
		$a_80_9 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 57 } //LookupAccountNameW  1
		$a_80_10 = {57 49 4e 48 54 54 50 2e 64 6c 6c } //WINHTTP.dll  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=18
 
}
rule Trojan_Win32_IcedID_GG_MTB_2{
	meta:
		description = "Trojan:Win32/IcedID.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 61 64 6c 5f 33 32 2e 64 6c 6c } //sadl_32.dll  1
		$a_80_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_2 = {57 49 4e 48 54 54 50 2e 64 6c 6c } //WINHTTP.dll  1
		$a_80_3 = {3f 69 64 3d 25 30 2e 32 58 25 30 2e 38 58 25 30 2e 38 58 25 73 } //?id=%0.2X%0.8X%0.8X%s  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {57 72 69 74 65 46 69 6c 65 } //WriteFile  1
		$a_80_6 = {25 30 2e 38 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 2d 25 30 2e 34 58 25 30 2e 38 58 } //%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X  1
		$a_80_7 = {25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 38 58 } //%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}