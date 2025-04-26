
rule Trojan_BAT_AgentTesla_NJN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {ae 55 ba 4e 16 62 1a 59 ba 4e 28 00 23 90 da 7d 29 00 84 76 21 7c 13 66 41 53 6d 51 35 5f bb 9e 07 5c 4a 90 32 62 } //1
		$a_01_1 = {4d 61 68 6a 6f 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Mahjong.Properties.Resources.resources
		$a_01_2 = {24 33 33 64 61 38 34 30 61 2d 37 31 33 33 2d 34 66 35 61 2d 39 37 34 39 2d 63 30 62 35 62 35 39 32 38 38 36 37 } //1 $33da840a-7133-4f5a-9749-c0b5b5928867
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_6 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}