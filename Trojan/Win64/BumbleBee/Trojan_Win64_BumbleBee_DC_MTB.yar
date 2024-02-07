
rule Trojan_Win64_BumbleBee_DC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 77 6b 6c 72 77 38 38 34 72 67 37 30 2e 64 6c 6c } //01 00  nwklrw884rg70.dll
		$a_01_1 = {51 58 59 75 6f 6b 36 36 30 } //01 00  QXYuok660
		$a_01_2 = {71 75 42 6f 4e 53 6d 54 53 6c } //01 00  quBoNSmTSl
		$a_01_3 = {4d 66 72 30 37 41 37 34 } //00 00  Mfr07A74
	condition:
		any of ($a_*)
 
}