
rule Trojan_Win32_Injector_RPD_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 fa 05 0f b6 05 } //01 00 
		$a_01_1 = {c1 e0 03 0b d0 88 15 } //00 00 
	condition:
		any of ($a_*)
 
}