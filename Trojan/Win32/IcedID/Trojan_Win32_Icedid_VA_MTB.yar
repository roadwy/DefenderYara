
rule Trojan_Win32_Icedid_VA_MTB{
	meta:
		description = "Trojan:Win32/Icedid.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {51 6a 40 68 90 01 04 51 6a 00 ff 93 90 02 04 59 5e 89 83 90 02 04 89 c7 f3 a4 8b b3 90 02 04 8d bb 90 02 04 29 f7 01 f8 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}