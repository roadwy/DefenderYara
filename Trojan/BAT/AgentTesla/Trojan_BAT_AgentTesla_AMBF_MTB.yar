
rule Trojan_BAT_AgentTesla_AMBF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 71 00 75 00 2e 00 61 00 78 00 } //1 https://qu.ax
		$a_80_1 = {4b 68 65 69 6f 74 72 6a 2b 3c 4f 69 6b 6f 68 65 72 67 3e 64 5f 5f 31 } //Kheiotrj+<Oikoherg>d__1  1
		$a_80_2 = {48 74 74 70 43 6c 69 65 6e 74 } //HttpClient  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}