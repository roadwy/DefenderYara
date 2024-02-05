
rule Trojan_Win32_Injector_BK_bit{
	meta:
		description = "Trojan:Win32/Injector.BK!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 fb 8b 7c 90 01 02 31 fb 33 5c 90 01 02 8b 7c 90 01 02 31 fb 89 5c 90 01 02 68 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}