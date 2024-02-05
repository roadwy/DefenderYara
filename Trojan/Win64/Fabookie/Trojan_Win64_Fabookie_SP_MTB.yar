
rule Trojan_Win64_Fabookie_SP_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 0f b6 01 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 01 83 c0 01 41 3b c0 75 } //00 00 
	condition:
		any of ($a_*)
 
}