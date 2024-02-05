
rule Trojan_Win64_Apolmy_A{
	meta:
		description = "Trojan:Win64/Apolmy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {48 a3 0b 00 00 00 01 00 00 00 b0 04 a2 25 00 00 00 01 00 00 00 } //01 00 
		$a_01_1 = {48 b8 fb ff ff ff 00 00 00 00 48 83 c4 38 } //01 00 
		$a_01_2 = {b8 fb ff ff ff 48 83 c4 38 } //00 00 
		$a_00_3 = {5d 04 00 } //00 12 
	condition:
		any of ($a_*)
 
}