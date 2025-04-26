
rule Trojan_Win64_BumbleBee_DC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 77 6b 6c 72 77 38 38 34 72 67 37 30 2e 64 6c 6c } //1 nwklrw884rg70.dll
		$a_01_1 = {51 58 59 75 6f 6b 36 36 30 } //1 QXYuok660
		$a_01_2 = {71 75 42 6f 4e 53 6d 54 53 6c } //1 quBoNSmTSl
		$a_01_3 = {4d 66 72 30 37 41 37 34 } //1 Mfr07A74
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}