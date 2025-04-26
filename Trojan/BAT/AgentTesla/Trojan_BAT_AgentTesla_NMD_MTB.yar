
rule Trojan_BAT_AgentTesla_NMD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 32 00 30 } //1
		$a_80_1 = {31 38 35 2e 32 32 32 2e 35 38 2e 35 36 2f 63 6f 75 73 69 6e 2e 70 6e 67 } //185.222.58.56/cousin.png  1
		$a_80_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //GetByteArrayAsync  1
		$a_80_3 = {52 65 76 65 72 73 65 } //Reverse  1
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_80_5 = {4d 78 6c 63 69 70 69 79 6f 6d 6b 6a 61 78 2e 51 7a 77 70 7a 62 68 6b 61 } //Mxlcipiyomkjax.Qzwpzbhka  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}