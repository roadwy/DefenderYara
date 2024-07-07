
rule Trojan_BAT_Agenttesla_EVD_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.EVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 14 ed f4 d5 0d 87 c3 37 07 d6 21 e1 cd e6 e7 d3 fb c8 d8 a1 e6 81 02 44 14 53 d6 2f 10 5d e9 b6 c7 aa 26 5e 5a 51 c0 40 b3 40 f6 1e 25 62 49 } //1
		$a_01_1 = {d8 fd 46 95 01 a8 30 46 13 47 87 c6 2a f5 7c 0f af c1 bd ce ee 24 20 70 db e8 c7 b7 56 d7 6a a4 78 cd f2 14 ba ba 8b 5c da d4 49 b7 7c 01 52 36 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}