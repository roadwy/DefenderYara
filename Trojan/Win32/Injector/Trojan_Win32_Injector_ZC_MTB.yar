
rule Trojan_Win32_Injector_ZC_MTB{
	meta:
		description = "Trojan:Win32/Injector.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 33 81 ea 90 01 04 01 d2 81 c0 01 00 00 00 43 29 c2 ba 90 01 04 09 d2 39 cb 75 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}