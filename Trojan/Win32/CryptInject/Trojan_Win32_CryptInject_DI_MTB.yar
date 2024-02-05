
rule Trojan_Win32_CryptInject_DI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 42 90 46 90 e9 } //02 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}