
rule Trojan_Win64_Grandoreiro_psyF_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {8a 07 33 d2 88 06 46 47 85 c9 76 0b 8d 04 0a 01 45 10 42 3b d1 72 f5 8b c1 49 85 c0 75 e2 } //00 00 
	condition:
		any of ($a_*)
 
}