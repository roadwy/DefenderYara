
rule Trojan_Win32_Ekstak_KAA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 c4 0a 00 05 30 e1 b4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}