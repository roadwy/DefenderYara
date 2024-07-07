
rule Trojan_Win64_Grandoreiro_psyE_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 b8 99 04 00 00 b9 98 44 40 00 8a 19 80 eb f2 c0 c3 02 28 cb c0 cb 01 88 19 49 48 75 ed b8 90 02 09 8a 19 c0 c3 07 c0 cb 02 28 cb 80 f3 91 88 19 49 48 75 ed 5b 58 81 c1 1a 2c 00 00 ff e1 90 00 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}