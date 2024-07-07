
rule Trojan_Win32_MarsStealer_MC_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 c7 f3 a4 c6 07 5c 83 c7 01 8d 35 90 01 04 b9 22 00 00 00 f3 a4 83 c7 01 89 3d 90 01 04 59 8d 35 90 01 04 f3 a4 c6 07 5c 83 c7 01 8d 35 90 01 04 b9 0c 00 00 00 f3 a4 e9 90 00 } //5
		$a_01_1 = {4d 61 72 73 53 74 65 61 6c 65 72 38 5f 63 72 61 63 6b 65 64 5f 62 79 5f } //5 MarsStealer8_cracked_by_
		$a_01_2 = {4c 4c 43 50 50 43 } //5 LLCPPC
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {43 00 6f 00 64 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 70 00 61 00 73 00 73 00 } //1 Code encryption pass
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=17
 
}