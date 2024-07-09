
rule Trojan_Win32_Emotetcrypt_VI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 01 8b 4d ?? 30 04 ?? 47 8b 4d ?? 5e 3b 7d ?? 0f 8c 90 0a 1e 00 0f b6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VI_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 fa 8d [0-02] 88 54 [0-02] e8 [0-04] 8b 0d [0-04] 0f b6 [0-02] 0f b6 [0-02] 03 c2 99 bb [0-04] f7 fb 45 0f b6 [0-02] 8a 0c [0-02] 8b 44 [0-02] 30 4c [0-02] 3b 6c [0-02] 7c } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}