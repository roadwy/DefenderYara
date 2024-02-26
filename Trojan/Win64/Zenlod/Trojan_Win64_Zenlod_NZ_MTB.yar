
rule Trojan_Win64_Zenlod_NZ_MTB{
	meta:
		description = "Trojan:Win64/Zenlod.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 c1 e2 20 48 0b d0 48 89 55 90 01 01 48 8b 45 10 24 90 01 01 3c 06 75 32 8b 05 49 78 01 00 83 c8 08 90 00 } //05 00 
		$a_01_1 = {eb 14 e8 78 4f 00 00 84 c0 75 09 33 c9 e8 95 24 00 00 eb ea 8a c3 48 83 c4 } //00 00 
	condition:
		any of ($a_*)
 
}