
rule Trojan_Win32_Injector_RPL_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 db 74 01 ea 31 10 90 02 10 81 c0 04 00 00 00 90 02 10 39 f8 75 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}