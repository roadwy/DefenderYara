
rule Trojan_BAT_LokiBot_FM_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 2b 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 7a 00 00 00 30 00 00 00 83 00 00 00 5f } //10
		$a_01_1 = {24 65 63 38 34 32 36 62 65 2d 65 31 35 34 2d 34 66 30 65 2d 38 62 32 35 2d 62 63 66 32 63 38 64 62 30 32 62 34 } //1 $ec8426be-e154-4f0e-8b25-bcf2c8db02b4
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}