
rule Trojan_Win32_Ekstak_ASFP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a1 14 51 00 d6 71 4d 00 00 d2 0a 00 ed db 3a } //00 00 
	condition:
		any of ($a_*)
 
}