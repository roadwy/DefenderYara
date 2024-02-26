
rule Trojan_Win64_ZgRat_AZ_MTB{
	meta:
		description = "Trojan:Win64/ZgRat.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ba 65 38 32 38 63 35 61 33 48 89 54 24 1c 48 ba 38 35 37 37 65 34 64 31 48 89 54 24 24 48 ba 63 30 62 37 64 33 34 39 48 89 54 24 2c 48 ba 33 63 36 36 37 31 35 35 48 89 54 24 34 31 c0 } //00 00 
	condition:
		any of ($a_*)
 
}