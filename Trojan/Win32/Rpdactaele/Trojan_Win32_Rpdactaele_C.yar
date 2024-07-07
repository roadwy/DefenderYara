
rule Trojan_Win32_Rpdactaele_C{
	meta:
		description = "Trojan:Win32/Rpdactaele.C,SIGNATURE_TYPE_PEHSTR_EXT,6a 04 6a 04 05 00 00 "
		
	strings :
		$a_80_0 = {5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c } //\..\..\..\..\..\  1000
		$a_80_1 = {34 63 39 64 62 66 31 39 2d 64 33 39 65 2d 34 62 62 39 2d 39 30 65 65 2d 38 66 37 31 37 39 62 32 30 32 38 33 00 } //4c9dbf19-d39e-4bb9-90ee-8f7179b20283  100
		$a_80_2 = {6e 63 61 6c 72 70 63 } //ncalrpc  10
		$a_80_3 = {52 70 63 42 69 6e 64 69 6e 67 53 65 74 41 75 74 68 49 6e 66 6f 45 78 57 } //RpcBindingSetAuthInfoExW  10
		$a_80_4 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwSetInformationFile  10
	condition:
		((#a_80_0  & 1)*1000+(#a_80_1  & 1)*100+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10) >=1130
 
}