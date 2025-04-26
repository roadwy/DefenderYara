
rule Trojan_Win32_Bazzarldr_GU_MTB{
	meta:
		description = "Trojan:Win32/Bazzarldr.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_02_0 = {10 00 00 c7 44 [0-02] 00 00 00 00 89 04 [0-02] ff d3 8b 4d [0-02] 89 c7 89 c3 f3 a4 83 ec [0-02] 89 5c [0-02] c7 44 [0-02] 00 00 00 00 8b 45 [0-02] c7 44 [0-02] 01 00 00 00 c7 44 [0-02] 00 00 00 00 89 44 [0-02] 8d 45 [0-02] 89 44 [0-02] 8b 45 [0-02] 89 04 [0-02] ff 15 [0-04] 83 ec [0-02] 85 c0 0f } //5
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  1
		$a_80_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
		$a_80_3 = {6d 65 6d 63 70 79 } //memcpy  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}