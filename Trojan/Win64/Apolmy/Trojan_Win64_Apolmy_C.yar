
rule Trojan_Win64_Apolmy_C{
	meta:
		description = "Trojan:Win64/Apolmy.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 b9 0b 00 00 00 01 00 00 00 48 8b 44 24 90 01 01 48 89 01 48 b8 25 00 00 00 01 00 00 00 c6 00 04 90 00 } //02 00 
		$a_03_1 = {48 b8 0b 00 00 00 01 00 00 00 48 8b 4c 24 90 01 01 48 89 08 48 b8 25 00 00 00 01 00 00 00 c6 00 04 90 00 } //01 00 
		$a_01_2 = {48 b8 fb ff ff ff 00 00 00 00 48 83 c4 38 } //01 00 
		$a_01_3 = {b8 fb ff ff ff 48 83 c4 38 } //00 00 
	condition:
		any of ($a_*)
 
}