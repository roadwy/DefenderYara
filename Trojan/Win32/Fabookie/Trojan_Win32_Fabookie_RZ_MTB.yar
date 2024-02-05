
rule Trojan_Win32_Fabookie_RZ_MTB{
	meta:
		description = "Trojan:Win32/Fabookie.RZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 04 24 00 00 00 00 8b 44 24 10 89 04 24 8b 44 24 0c 31 04 24 8b 04 24 8b 4c 24 08 89 01 59 c2 0c 00 } //00 00 
	condition:
		any of ($a_*)
 
}