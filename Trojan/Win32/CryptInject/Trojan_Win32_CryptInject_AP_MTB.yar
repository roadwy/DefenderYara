
rule Trojan_Win32_CryptInject_AP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 34 c6 44 24 44 74 88 54 24 46 c6 44 24 40 43 c6 44 24 39 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_AP_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 d2 7e 0d e8 90 01 02 ff ff 30 04 0e 46 3b f2 7c f3 5e c3 90 00 } //01 00 
		$a_02_1 = {c1 e8 10 25 ff 7f 00 00 c3 90 0a 4f 00 69 05 90 01 03 00 90 01 04 05 90 01 04 a3 90 01 03 00 c1 e8 10 25 ff 7f 00 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}