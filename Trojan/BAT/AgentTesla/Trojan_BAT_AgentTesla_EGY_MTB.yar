
rule Trojan_BAT_AgentTesla_EGY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {09 08 1f 21 09 08 93 1f 0e 58 1f 5e 5d 58 28 ?? ?? ?? 0a 9d } //1
		$a_01_1 = {24 37 45 34 45 42 41 36 34 2d 38 35 36 32 2d 34 45 45 30 2d 41 43 41 36 2d 41 36 30 41 42 30 39 41 35 32 42 33 } //1 $7E4EBA64-8562-4EE0-ACA6-A60AB09A52B3
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //1 䘀潲䉭獡㙥匴牴湩g
		$a_01_3 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
		$a_01_4 = {00 47 65 74 54 79 70 65 } //1 䜀瑥祔数
		$a_01_5 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //1 䌀敲瑡䥥獮慴据e
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}