
rule Trojan_Win32_Cobaltstrike_AA_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 44 65 66 69 6e 69 74 65 51 } //1 InDefiniteQ
		$a_01_1 = {76 76 73 65 63 74 69 6f 6e } //1 vvsection
		$a_01_2 = {6e 6f 20 73 75 63 68 20 64 65 76 69 63 65 20 6f 72 20 61 64 64 72 65 73 73 } //1 no such device or address
		$a_01_3 = {46 6c 75 73 68 50 72 6f 63 65 73 73 57 72 69 74 65 42 75 66 66 65 72 73 } //1 FlushProcessWriteBuffers
		$a_01_4 = {69 6e 64 65 66 69 6e 69 74 65 38 36 2e 64 6c 6c } //1 indefinite86.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}