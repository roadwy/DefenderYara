
rule Trojan_Win32_Ekstak_ASEL_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {51 57 ff 15 90 01 03 00 8b f8 a1 90 01 03 00 8b c8 48 83 f9 01 a3 90 01 03 00 73 4f 56 8b 35 90 01 03 00 68 90 01 03 00 ff d6 8d 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}