
rule Trojan_Win32_Zenpak_BN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 64 72 4c 6f 61 64 44 6c 6c } //1 LdrLoadDll
		$a_01_1 = {73 6e 78 68 6b 2e 64 6c 6c } //1 snxhk.dll
		$a_01_2 = {46 4c 4e 3d 2d } //1 FLN=-
		$a_01_3 = {56 69 72 74 75 61 6c 51 75 65 72 79 } //1 VirtualQuery
		$a_01_4 = {46 72 65 65 43 6f 6e 73 6f 6c 65 } //1 FreeConsole
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}