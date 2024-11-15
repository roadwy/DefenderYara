
rule Trojan_Win64_MysticStealer_AMYS_MTB{
	meta:
		description = "Trojan:Win64/MysticStealer.AMYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 85 10 04 00 00 53 00 66 c7 85 12 04 00 00 5c 00 66 c7 85 14 04 00 00 48 00 66 c7 85 16 04 00 00 55 00 66 c7 85 18 04 00 00 59 00 66 c7 85 1a 04 00 00 51 00 66 c7 85 1c 04 00 00 0d 00 66 c7 85 1e 04 00 00 0d 00 66 c7 85 20 04 00 00 6e 00 66 c7 85 22 04 00 00 25 00 66 c7 85 24 04 00 00 2e 00 66 c7 85 26 04 00 00 2f 00 66 c7 85 28 04 00 00 44 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}