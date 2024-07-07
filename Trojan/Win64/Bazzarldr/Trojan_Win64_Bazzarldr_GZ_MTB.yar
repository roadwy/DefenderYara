
rule Trojan_Win64_Bazzarldr_GZ_MTB{
	meta:
		description = "Trojan:Win64/Bazzarldr.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 63 d0 48 8b 90 02 02 48 01 c2 8b 45 90 02 02 48 63 c8 48 8b 45 90 02 02 48 01 c8 0f b6 08 4c 8b 05 90 02 04 0f b6 45 90 02 02 4c 01 c0 0f b6 00 31 c8 88 02 83 45 90 02 02 01 8b 45 90 02 02 3b 45 90 02 02 0f 8c 90 00 } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
		$a_80_3 = {6d 65 6d 63 70 79 } //memcpy  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}