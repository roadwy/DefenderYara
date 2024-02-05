
rule Trojan_Win32_Rpdactaele_C{
	meta:
		description = "Trojan:Win32/Rpdactaele.C,SIGNATURE_TYPE_PEHSTR_EXT,6a 04 6a 04 05 00 00 ffffffe8 03 "
		
	strings :
		$a_80_0 = {5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c } //\..\..\..\..\..\  64 00 
		$a_80_1 = {34 63 39 64 62 66 31 39 2d 64 33 39 65 2d 34 62 62 39 2d 39 30 65 65 2d 38 66 37 31 37 39 62 32 30 32 38 33 00 } //4c9dbf19-d39e-4bb9-90ee-8f7179b20283  0a 00 
		$a_80_2 = {6e 63 61 6c 72 70 63 } //ncalrpc  0a 00 
		$a_80_3 = {52 70 63 42 69 6e 64 69 6e 67 53 65 74 41 75 74 68 49 6e 66 6f 45 78 57 } //RpcBindingSetAuthInfoExW  0a 00 
		$a_80_4 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //ZwSetInformationFile  00 00 
		$a_04_5 = {5d 04 00 00 14 be 03 80 5c 2c 00 00 17 be 03 80 00 00 01 00 32 00 16 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 54 6f 73 74 68 69 6e 2e 41 00 00 03 40 05 82 70 00 04 00 7e 15 00 00 58 0f 16 20 17 65 a3 9f 20 fd f8 c0 d0 69 8f 36 ad 77 b0 95 4d 7e 15 00 00 69 } //ac 53 
	condition:
		any of ($a_*)
 
}