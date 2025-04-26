
rule Trojan_BAT_AgentTesla_NEJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {33 62 30 65 62 37 36 33 2d 32 66 33 66 2d 34 35 39 62 2d 61 38 37 62 2d 37 36 35 35 61 32 35 63 30 62 36 35 } //1 3b0eb763-2f3f-459b-a87b-7655a25c0b65
		$a_01_1 = {4b 69 6e 6f 6d 61 6e 69 61 6b 20 4c 69 62 72 61 72 79 } //2 Kinomaniak Library
		$a_01_2 = {4b 6f 6d 65 64 69 61 52 6f 6d 61 6e 74 79 63 7a 6e 61 } //2 KomediaRomantyczna
		$a_01_3 = {46 75 6c 6c 49 6e 66 6f 57 79 73 7a 75 6b 61 6a } //2 FullInfoWyszukaj
		$a_01_4 = {41 6b 63 6a 61 } //1 Akcja
		$a_01_5 = {57 6f 6a 65 6e 6e 79 } //1 Wojenny
		$a_01_6 = {41 6e 69 6d 6f 77 61 6e 79 } //1 Animowany
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}