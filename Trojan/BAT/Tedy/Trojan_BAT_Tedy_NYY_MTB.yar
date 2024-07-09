
rule Trojan_BAT_Tedy_NYY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 02 00 00 04 a2 25 18 72 ?? 00 00 70 a2 25 19 28 ?? 00 00 0a a2 25 1a 72 ?? 00 00 70 a2 25 1b 7e ?? 00 00 04 a2 28 ?? 00 00 0a 28 ?? 00 00 06 00 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 06 } //5
		$a_01_1 = {41 73 73 69 73 74 65 6e 74 65 2e 50 72 6f 67 72 61 6d } //1 Assistente.Program
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}