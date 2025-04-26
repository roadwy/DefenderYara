
rule Trojan_BAT_AgentTesla_NRG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {42 6f 76 6c 62 68 61 78 6a 64 74 } //Bovlbhaxjdt  1
		$a_01_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_80_2 = {4b 64 70 6c 70 70 76 75 67 79 6f 73 6d 62 74 6c 78 6a 63 6c 7a 72 61 2e 4d 7a 6a 6c 61 69 65 69 6f 73 76 6f 73 6e 68 62 6d 66 } //Kdplppvugyosmbtlxjclzra.Mzjlaieiosvosnhbmf  1
		$a_80_3 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //cdn.discordapp.com  1
		$a_80_4 = {35 34 36 39 30 32 34 31 5f 58 79 72 67 6f 63 6b 74 2e 62 6d 70 } //54690241_Xyrgockt.bmp  1
		$a_01_5 = {37 31 65 65 61 35 62 35 2d 31 31 39 36 } //1 71eea5b5-1196
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}