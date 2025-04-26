
rule Trojan_Win64_SnakeKeylogger_SPK_MTB{
	meta:
		description = "Trojan:Win64/SnakeKeylogger.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b d1 41 b9 04 00 00 00 33 c9 44 8b c7 48 8b 74 24 48 48 83 c4 30 5f 48 ff 25 ac ca 32 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}