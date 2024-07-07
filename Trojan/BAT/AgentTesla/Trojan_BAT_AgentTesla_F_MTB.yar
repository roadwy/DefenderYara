
rule Trojan_BAT_AgentTesla_F_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {66 00 64 00 66 00 72 00 66 00 2e 00 64 00 6c 00 6c 00 } //1 fdfrf.dll
		$a_01_1 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 00 67 65 74 5f 4d 6f 64 75 6c 65 4e 61 6d 65 00 47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 00 41 73 73 65 6d 62 6c 79 4e 61 6d 65 } //1 敇剴湡潤䙭汩乥浡e敧彴潍畤敬慎敭䜀瑥牐捯獥敳䉳乹浡e獁敳扭祬慎敭
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}