
rule Trojan_Win32_Injector_EPQX_MTB{
	meta:
		description = "Trojan:Win32/Injector.EPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 83 c6 00 83 } //01 00 
		$a_02_1 = {d2 d2 d2 d2 83 ea 00 81 34 2f 90 01 04 83 e8 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Injector_EPQX_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.EPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 34 0b 5a 81 f2 90 01 04 09 14 0f 83 c1 fc 90 00 } //01 00 
		$a_81_1 = {55 74 69 6c 67 69 76 65 6c 69 67 68 65 64 65 72 6e 65 73 31 } //01 00 
		$a_81_2 = {53 61 6d 6d 65 6e 74 72 79 6b 6b 65 73 32 } //01 00 
		$a_81_3 = {54 65 6d 70 6f 72 69 73 65 72 73 34 } //00 00 
	condition:
		any of ($a_*)
 
}