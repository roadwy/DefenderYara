
rule Trojan_Win32_Injector_RPM_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {74 01 ea 31 1e 90 02 10 81 c6 04 00 00 00 90 02 20 39 fe 75 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}