
rule Trojan_Win32_CryptInject_DW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 [0-04] 8b 94 24 [0-04] 01 c2 31 ca 88 94 04 [0-04] 83 c0 01 83 f8 2d 75 de } //1
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}