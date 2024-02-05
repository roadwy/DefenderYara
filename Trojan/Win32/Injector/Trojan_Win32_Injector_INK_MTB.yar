
rule Trojan_Win32_Injector_INK_MTB{
	meta:
		description = "Trojan:Win32/Injector.INK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 0c 00 00 00 32 37 34 39 41 38 45 43 42 34 30 32 00 00 00 00 ff } //00 00 
	condition:
		any of ($a_*)
 
}