
rule Trojan_Win32_Ekstak_ASFK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {51 ff d6 8b 15 90 01 03 00 68 90 01 03 00 52 a3 90 01 03 00 ff d6 a3 90 01 03 00 5e 59 c3 a1 90 01 03 00 68 90 01 03 00 50 ff d6 a3 90 01 03 00 5e 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}