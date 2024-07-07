
rule Trojan_Win64_Dridex_QR_MTB{
	meta:
		description = "Trojan:Win64/Dridex.QR!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 8c 24 48 01 00 00 48 89 f1 48 89 f7 48 d3 ef 48 89 bc 24 b0 04 00 00 4c 89 c9 49 89 f1 49 d3 e9 4c 89 8c 24 b0 04 00 00 8b 94 24 b8 04 00 00 89 d1 89 d3 d3 e3 89 9c 24 b8 04 00 00 } //10
		$a_01_1 = {88 4c 24 47 d3 ea 89 94 24 9c 01 00 00 89 c2 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}