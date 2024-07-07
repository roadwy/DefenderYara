
rule Ransom_Win32_NetWalker_MTB{
	meta:
		description = "Ransom:Win32/NetWalker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 03 c8 0f b6 c1 8b 4c 24 90 01 01 0f b6 04 90 01 01 30 04 0e 46 8b 4c 24 90 01 01 3b f5 72 90 0a c0 00 8d 90 01 01 01 0f b6 90 01 01 8a 14 90 01 01 0f b6 c2 03 c1 0f b6 c8 89 4c 24 1c 0f b6 04 90 01 01 88 04 90 01 01 88 14 90 01 01 0f b6 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_NetWalker_MTB_2{
	meta:
		description = "Ransom:Win32/NetWalker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 16-byte k
		$a_01_1 = {6e 00 73 00 74 00 6f 00 70 00 6d 00 61 00 72 00 6b 00 65 00 72 00 } //1 nstopmarker
		$a_01_2 = {54 68 65 20 6e 65 74 77 6f 72 6b 20 69 73 20 6c 6f 63 6b 65 64 } //1 The network is locked
		$a_01_3 = {49 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 } //1 If you do not pay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}