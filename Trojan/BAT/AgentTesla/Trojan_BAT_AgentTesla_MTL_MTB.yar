
rule Trojan_BAT_AgentTesla_MTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {54 6f 6b 65 6e 69 7a 65 72 } //Tokenizer  1
		$a_80_1 = {56 61 72 69 61 6e 74 } //Variant  1
		$a_80_2 = {44 61 74 61 5f 31 } //Data_1  1
		$a_80_3 = {52 6f 75 6e 64 } //Round  1
		$a_80_4 = {58 73 64 54 79 70 65 } //XsdType  1
		$a_80_5 = {42 69 74 6d 61 70 } //Bitmap  1
		$a_80_6 = {47 65 74 54 79 70 65 73 } //GetTypes  1
		$a_80_7 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
		$a_80_8 = {41 5a 54 46 47 41 34 34 47 47 34 59 38 55 32 34 34 35 47 49 56 35 } //AZTFGA44GG4Y8U2445GIV5  1
		$a_80_9 = {67 65 74 5f 53 79 6e 63 } //get_Sync  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}