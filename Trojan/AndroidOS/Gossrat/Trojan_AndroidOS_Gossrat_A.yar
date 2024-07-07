
rule Trojan_AndroidOS_Gossrat_A{
	meta:
		description = "Trojan:AndroidOS/Gossrat.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 68 74 79 46 58 4a 76 7a 6b 6f 38 50 4c 2b 67 39 2b 78 55 35 77 3d 3d } //1 NhtyFXJvzko8PL+g9+xU5w==
		$a_01_1 = {53 66 66 66 6b 79 71 41 52 58 42 32 64 67 34 4b 6f 7a 7a 5a 38 67 3d 3d } //1 SfffkyqARXB2dg4KozzZ8g==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}