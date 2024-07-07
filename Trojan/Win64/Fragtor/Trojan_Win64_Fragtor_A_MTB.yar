
rule Trojan_Win64_Fragtor_A_MTB{
	meta:
		description = "Trojan:Win64/Fragtor.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ac fe c8 f6 d8 2c 90 01 01 c0 c8 90 01 01 34 90 01 01 fe c8 88 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}