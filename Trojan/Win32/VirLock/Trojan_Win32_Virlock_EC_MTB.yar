
rule Trojan_Win32_Virlock_EC_MTB{
	meta:
		description = "Trojan:Win32/Virlock.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {b9 00 04 00 00 ba 04 00 00 00 8a 06 32 c2 90 e9 b8 ff ff ff } //02 00 
		$a_01_1 = {89 07 90 8b f8 8b df 90 e9 34 00 00 00 88 07 42 46 47 90 49 90 83 f9 00 90 e9 } //00 00 
	condition:
		any of ($a_*)
 
}