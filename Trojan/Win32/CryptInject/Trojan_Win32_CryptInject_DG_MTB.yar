
rule Trojan_Win32_CryptInject_DG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 14 0c 32 14 29 83 c0 01 80 f2 8d 88 11 83 c1 01 83 ef 01 75 da } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}