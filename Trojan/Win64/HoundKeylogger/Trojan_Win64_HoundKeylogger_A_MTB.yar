
rule Trojan_Win64_HoundKeylogger_A_MTB{
	meta:
		description = "Trojan:Win64/HoundKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 88 ff ff ff 48 89 5c 24 20 45 33 c0 33 d2 b9 00 08 00 00 ff 15 90 01 04 b9 01 00 00 00 ff 15 90 01 04 b9 05 00 00 00 ff 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}