
rule Trojan_Win32_MatanbuchusLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {36 30 30 31 2e 69 63 6c } //1 6001.icl
		$a_01_1 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_3 = {44 33 44 4b 4d 54 51 75 65 72 79 41 64 61 70 74 65 72 49 6e 66 6f } //1 D3DKMTQueryAdapterInfo
		$a_01_4 = {44 33 44 4b 4d 54 4f 70 65 6e 41 64 61 70 74 65 72 46 72 6f 6d 44 65 76 69 63 65 4e 61 6d 65 } //1 D3DKMTOpenAdapterFromDeviceName
		$a_01_5 = {63 74 23 65 61 75 52 69 63 68 22 65 61 75 } //1 ct#eauRich"eau
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}