
rule Trojan_Win64_PswStealer_MTB{
	meta:
		description = "Trojan:Win64/PswStealer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 f8 0b 77 27 42 0f b6 4c 10 02 c1 e1 10 42 0f b7 14 10 01 d1 81 c1 00 00 00 07 41 33 0c 00 89 8c 04 00 01 00 00 48 83 c0 04 } //00 00 
	condition:
		any of ($a_*)
 
}