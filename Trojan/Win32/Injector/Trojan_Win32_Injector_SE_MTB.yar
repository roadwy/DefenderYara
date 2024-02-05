
rule Trojan_Win32_Injector_SE_MTB{
	meta:
		description = "Trojan:Win32/Injector.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 02 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 6a 90 01 01 e8 90 01 04 8b 55 90 01 01 03 55 90 01 01 2b d0 8b 45 90 01 01 31 10 68 90 01 04 e8 90 01 04 8b d8 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}