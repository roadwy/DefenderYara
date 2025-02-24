
rule Trojan_Win64_CoffeeBean_A_dha{
	meta:
		description = "Trojan:Win64/CoffeeBean.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 69 69 78 20 51 12 81 80 17 12 34 10 67 11 14 16 13 33 21 39 49 45 13 85 10 87 22 96 10 64 46 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}