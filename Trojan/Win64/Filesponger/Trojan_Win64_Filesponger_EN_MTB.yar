
rule Trojan_Win64_Filesponger_EN_MTB{
	meta:
		description = "Trojan:Win64/Filesponger.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 10 a8 27 00 33 c9 } //5
		$a_01_1 = {45 33 c9 45 33 c0 ba a0 c5 7f 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}