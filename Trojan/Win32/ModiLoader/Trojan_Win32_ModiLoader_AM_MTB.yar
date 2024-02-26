
rule Trojan_Win32_ModiLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 34 38 8b c1 83 c1 02 99 2b c2 8a 54 0e 08 d1 f8 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}