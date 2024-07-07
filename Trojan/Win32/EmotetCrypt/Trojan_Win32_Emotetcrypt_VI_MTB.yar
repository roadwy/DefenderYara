
rule Trojan_Win32_Emotetcrypt_VI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 8b 4d 90 01 01 30 04 90 01 01 47 8b 4d 90 01 01 5e 3b 7d 90 01 01 0f 8c 90 0a 1e 00 0f b6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VI_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 fa 8d 90 02 02 88 54 90 02 02 e8 90 02 04 8b 0d 90 02 04 0f b6 90 02 02 0f b6 90 02 02 03 c2 99 bb 90 02 04 f7 fb 45 0f b6 90 02 02 8a 0c 90 02 02 8b 44 90 02 02 30 4c 90 02 02 3b 6c 90 02 02 7c 90 00 } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}