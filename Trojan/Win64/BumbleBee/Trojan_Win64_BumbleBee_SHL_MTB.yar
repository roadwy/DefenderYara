
rule Trojan_Win64_BumbleBee_SHL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 b3 88 00 22 00 49 81 83 90 00 22 00 a6 fe 00 00 49 8b b3 88 00 22 00 48 81 c4 48 00 00 00 49 bc 78 04 36 b4 02 03 81 4b 4c 29 e6 4c 01 de 48 ff e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}