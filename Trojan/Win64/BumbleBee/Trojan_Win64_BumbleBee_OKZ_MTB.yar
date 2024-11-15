
rule Trojan_Win64_BumbleBee_OKZ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 05 8e a0 04 00 48 8b 0d bb a0 04 00 31 04 31 48 83 c6 04 4c 8b 05 15 a0 04 00 8b 05 af a0 04 00 01 05 6d a0 04 00 8b 15 e7 a0 04 00 01 15 51 a0 04 00 41 8b 48 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}