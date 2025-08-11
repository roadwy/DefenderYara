
rule Trojan_Win32_AgentTesla_RVG_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 6f 79 5c 61 76 69 63 75 6c 61 72 69 6d 6f 72 70 68 61 65 5c 6b 6d 70 65 73 74 6f 72 65 } //1 soy\avicularimorphae\kmpestore
		$a_81_1 = {5c 61 61 6e 64 73 61 72 62 65 6a 64 65 72 65 5c 66 69 64 75 73 65 6e } //1 \aandsarbejdere\fidusen
		$a_81_2 = {64 69 73 63 6f 6d 6d 6f 64 69 6f 75 73 6c 79 20 66 6f 6e 64 73 61 6b 74 69 65 6e 73 20 74 72 79 6b 73 74 62 6e 69 6e 67 73 } //1 discommodiously fondsaktiens trykstbnings
		$a_81_3 = {69 72 6b 65 20 75 74 61 6b 6e 65 6d 6c 69 67 68 65 64 65 6e 20 73 6f 66 61 73 } //1 irke utaknemligheden sofas
		$a_81_4 = {68 65 72 6c 69 67 68 65 64 73 76 72 64 69 65 72 6e 65 20 70 61 61 73 65 6a 6c 65 72 } //1 herlighedsvrdierne paasejler
		$a_81_5 = {61 70 70 6c 69 61 62 6c 65 20 64 65 63 61 6c 63 69 66 69 65 73 20 62 6c 65 67 66 65 64 74 } //1 appliable decalcifies blegfedt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}