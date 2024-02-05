
rule Trojan_BAT_AgentTesla_MSM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 13 00 00 01 00 "
		
	strings :
		$a_80_0 = {56 61 72 69 61 6e 74 } //Variant  01 00 
		$a_80_1 = {67 65 74 5f 53 63 61 6c 61 72 } //get_Scalar  01 00 
		$a_80_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  01 00 
		$a_80_3 = {58 73 64 54 79 70 65 } //XsdType  01 00 
		$a_80_4 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_5 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_6 = {53 63 61 6c 61 72 } //Scalar  01 00 
		$a_80_7 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //get_Assembly  01 00 
		$a_80_8 = {43 6f 6e 63 61 74 } //Concat  01 00 
		$a_80_9 = {47 65 74 4f 62 6a 65 63 74 } //GetObject  01 00 
		$a_80_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //DebuggingModes  01 00 
		$a_80_11 = {45 6e 63 6f 64 69 6e 67 } //Encoding  01 00 
		$a_80_12 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //get_ResourceManager  01 00 
		$a_80_13 = {43 6f 6d 70 6f 6e 65 6e 74 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ComponentResourceManager  01 00 
		$a_80_14 = {54 6f 6b 65 6e 69 7a 65 72 } //Tokenizer  01 00 
		$a_80_15 = {42 69 74 6d 61 70 } //Bitmap  01 00 
		$a_80_16 = {41 70 70 44 6f 6d 61 69 6e } //AppDomain  01 00 
		$a_80_17 = {54 6f 53 74 72 69 6e 67 } //ToString  0a 00 
		$a_80_18 = {35 35 33 55 42 4b 37 42 47 46 46 34 38 38 5a 35 34 38 5a 55 35 46 } //553UBK7BGFF488Z548ZU5F  00 00 
	condition:
		any of ($a_*)
 
}