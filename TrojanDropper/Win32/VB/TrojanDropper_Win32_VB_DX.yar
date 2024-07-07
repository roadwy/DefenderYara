
rule TrojanDropper_Win32_VB_DX{
	meta:
		description = "TrojanDropper:Win32/VB.DX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {0c 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 0e 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1
		$a_00_1 = {45 00 73 00 63 00 72 00 69 00 74 00 6f 00 72 00 69 00 6f 00 5c 00 53 00 74 00 75 00 62 00 32 00 5c 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 } //1 Escritorio\Stub2\Stub.vbp
		$a_01_2 = {42 69 6c 6c 61 72 32 } //1 Billar2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}