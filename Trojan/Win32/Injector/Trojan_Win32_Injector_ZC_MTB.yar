
rule Trojan_Win32_Injector_ZC_MTB{
	meta:
		description = "Trojan:Win32/Injector.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 33 81 ea ?? ?? ?? ?? 01 d2 81 c0 01 00 00 00 43 29 c2 ba ?? ?? ?? ?? 09 d2 39 cb 75 c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}