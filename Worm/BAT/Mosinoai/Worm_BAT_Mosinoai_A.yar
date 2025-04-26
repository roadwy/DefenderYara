
rule Worm_BAT_Mosinoai_A{
	meta:
		description = "Worm:BAT/Mosinoai.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 6b 69 6c 6c 65 72 } //1 Botkiller
		$a_01_1 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //1 antiSandboxie
		$a_01_2 = {53 74 61 72 74 52 75 73 6b 69 6c 6c } //1 StartRuskill
		$a_00_3 = {41 00 52 00 4d 00 45 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 20 00 6f 00 6e 00 } //1 ARME flood on
		$a_00_4 = {53 00 6c 00 6f 00 77 00 6c 00 6f 00 72 00 69 00 73 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 20 00 6f 00 6e 00 } //1 Slowloris flood on
		$a_00_5 = {20 00 55 00 53 00 42 00 20 00 4c 00 4e 00 4b 00 20 00 73 00 70 00 72 00 65 00 61 00 64 00 20 00 6f 00 6e 00 } //1  USB LNK spread on
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}