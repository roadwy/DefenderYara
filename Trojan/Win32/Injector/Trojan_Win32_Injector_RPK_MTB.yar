
rule Trojan_Win32_Injector_RPK_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 c9 74 01 ea 31 32 90 02 10 81 c2 04 00 00 00 90 02 10 39 ca 75 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}