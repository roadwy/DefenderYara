
rule Trojan_BAT_AgentTesla_DTQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 84 6f c6 86 d4 9f fc 8c 67 91 2f f5 86 ee 0e dc 75 22 83 7a 5b a7 d1 47 ec 29 fc 23 57 ea 09 7f e3 ac e7 97 a5 27 fe 7b 92 27 7e fd ea 19 3f } //01 00 
		$a_01_1 = {72 a7 ac f1 81 6f f9 78 86 6f 9e c6 26 cf c8 63 fc e9 67 da 11 f9 a3 97 d3 98 dd 90 ef 3a be 5b 9f } //00 00 
	condition:
		any of ($a_*)
 
}