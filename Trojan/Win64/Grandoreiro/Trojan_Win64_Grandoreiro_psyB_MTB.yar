
rule Trojan_Win64_Grandoreiro_psyB_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 eb 1c e8 f1 01 00 00 85 c0 74 f3 ff 35 30 50 40 00 e8 90 01 03 ff 59 85 c0 74 e3 8b 45 0c 50 ff 15 54 40 40 90 00 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}