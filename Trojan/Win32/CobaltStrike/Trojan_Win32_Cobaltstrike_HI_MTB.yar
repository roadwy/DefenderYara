
rule Trojan_Win32_Cobaltstrike_HI_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 73 31 2e 64 6c 6c } //1 C:\Users\Public\Documents\s1.dll
		$a_01_1 = {66 61 69 6c 20 72 75 6e 6e 69 6e 67 20 73 74 65 70 32 } //1 fail running step2
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 20 66 61 69 6c 65 64 3a 20 25 64 } //1 Decompress failed: %d
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 20 66 61 69 6c 65 64 3a 20 25 64 } //1 CreateFile failed: %d
		$a_01_4 = {4e 74 44 43 6f 6d 70 6f 73 69 74 69 6f 6e 44 65 73 74 72 6f 79 43 68 61 6e 6e 65 6c } //1 NtDCompositionDestroyChannel
		$a_01_5 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_01_6 = {44 33 44 31 31 43 72 65 61 74 65 44 65 76 69 63 65 } //1 D3D11CreateDevice
		$a_01_7 = {54 68 69 73 20 70 72 00 6f 67 72 61 6d 20 63 61 00 6e 6e 6f 74 20 62 65 20 00 72 75 6e 20 69 6e 20 44 00 4f 53 20 6d 6f 64 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}