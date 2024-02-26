
rule Trojan_Win32_Ekstak_ASEP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 02 40 00 00 c0 0a 00 47 43 f4 14 90 01 02 40 00 00 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}