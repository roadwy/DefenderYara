
rule Trojan_Win32_Dridex_B_MTB{
	meta:
		description = "Trojan:Win32/Dridex.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fe 8b 4d e0 8a 3c 11 8b 75 c8 88 3c 31 88 1c 11 8b 4d f0 81 c1 [0-04] 8b 75 e0 8b 5d c8 0f b6 34 1e 01 fe 81 e6 [0-04] 8b 7d e8 8b 5d cc 8a 1c 1f 8b 7d e0 32 1c 37 8b 75 e4 8b 7d cc 88 1c 3e 01 cf 8b 4d ec 39 cf } //1
		$a_00_1 = {99 f7 f9 8b 4d b8 2b 4d f0 8b 7d e4 8b 5d bc 8a 1c 13 88 1f 8a 5d ef 8b 7d bc 88 1c 17 8b 7d e4 0f b6 3f 01 f7 21 cf 8b 4d bc 8a 1c 39 8b 75 d8 8b 7d c4 32 1c 37 8b 75 d8 8b 4d c0 88 1c 31 8b 75 d8 83 c6 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}