
rule Trojan_Win32_Injector_RPH_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 24 00 00 00 31 13 90 02 10 81 c3 01 00 00 00 90 02 10 39 c3 75 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}