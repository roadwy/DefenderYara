
rule Backdoor_BAT_Reverto_A{
	meta:
		description = "Backdoor:BAT/Reverto.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe d6 84 11 c2 80 6f 91 13 ef 83 cd 31 5a 08 b4 f8 3a 85 da a6 93 c4 ed 3a 46 95 50 b6 b1 82 ce a4 4b 08 9f 8c 10 4e 48 8a 9a b5 2d df 70 47 eb } //00 00 
	condition:
		any of ($a_*)
 
}