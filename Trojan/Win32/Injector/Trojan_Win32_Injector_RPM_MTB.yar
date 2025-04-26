
rule Trojan_Win32_Injector_RPM_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {74 01 ea 31 1e [0-10] 81 c6 04 00 00 00 [0-20] 39 fe 75 dc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}