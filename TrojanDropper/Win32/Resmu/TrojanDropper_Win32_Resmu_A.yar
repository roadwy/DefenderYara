
rule TrojanDropper_Win32_Resmu_A{
	meta:
		description = "TrojanDropper:Win32/Resmu.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 63 63 73 69 6e 66 5c 73 72 63 5c 6c 6f 61 64 65 72 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 6c 6f 61 64 65 72 2e 70 64 62 00 } //1
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 73 72 65 6e 75 6d 2e 73 79 73 00 } //1
		$a_01_2 = {25 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 72 75 6e 2e 65 78 65 00 } //1
		$a_01_3 = {6e 64 69 73 72 64 5f 6d 2e 69 6e 66 20 2d 63 20 73 20 2d 69 20 6e 74 5f 6e 64 69 73 72 64 } //1 ndisrd_m.inf -c s -i nt_ndisrd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}