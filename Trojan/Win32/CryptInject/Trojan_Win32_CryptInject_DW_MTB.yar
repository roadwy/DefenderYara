
rule Trojan_Win32_CryptInject_DW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 90 02 04 8b 94 24 90 02 04 01 c2 31 ca 88 94 04 90 02 04 83 c0 01 83 f8 2d 75 de 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}