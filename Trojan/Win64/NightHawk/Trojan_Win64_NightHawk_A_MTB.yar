
rule Trojan_Win64_NightHawk_A_MTB{
	meta:
		description = "Trojan:Win64/NightHawk.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 ca 66 89 94 44 90 01 04 48 83 c0 90 01 01 48 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}