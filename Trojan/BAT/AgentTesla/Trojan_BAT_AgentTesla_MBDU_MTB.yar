
rule Trojan_BAT_AgentTesla_MBDU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 40 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 40 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 40 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 Syste@m.Refl@ection.As@sembly
		$a_01_1 = {4c 00 6f 00 40 00 61 00 64 00 } //1 Lo@ad
		$a_01_2 = {47 00 65 00 40 00 74 00 45 00 78 00 70 00 40 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 40 00 70 00 65 00 73 00 } //1 Ge@tExp@ortedTy@pes
		$a_01_3 = {53 00 79 00 73 00 40 00 74 00 65 00 6d 00 2e 00 44 00 65 00 6c 00 40 00 65 00 67 00 61 00 74 00 65 00 } //1 Sys@tem.Del@egate
		$a_01_4 = {44 00 79 00 6e 00 40 00 61 00 6d 00 40 00 69 00 63 00 49 00 6e 00 76 00 40 00 6f 00 6b 00 65 00 } //1 Dyn@am@icInv@oke
		$a_01_5 = {43 00 72 00 40 00 65 00 61 00 74 00 65 00 44 00 65 00 40 00 6c 00 65 00 67 00 61 00 40 00 74 00 65 00 } //1 Cr@eateDe@lega@te
		$a_01_6 = {44 00 76 00 79 00 62 00 77 00 71 00 7a 00 61 00 } //1 Dvybwqza
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}