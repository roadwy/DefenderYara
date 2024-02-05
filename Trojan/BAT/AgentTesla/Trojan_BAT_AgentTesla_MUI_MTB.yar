
rule Trojan_BAT_AgentTesla_MUI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 79 6d 6d 65 74 72 69 63 44 65 63 } //SymmetricDec  01 00 
		$a_80_1 = {54 68 72 65 61 64 } //Thread  01 00 
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  01 00 
		$a_80_3 = {43 69 70 68 65 72 4d 6f 64 65 } //CipherMode  01 00 
		$a_80_4 = {44 61 74 61 49 4e 73 65 72 74 } //DataINsert  01 00 
		$a_80_5 = {56 61 6c 75 65 45 78 70 6f 72 74 } //ValueExport  01 00 
		$a_80_6 = {43 61 70 74 49 74 } //CaptIt  01 00 
		$a_80_7 = {67 65 74 5f 43 61 70 74 49 74 } //get_CaptIt  01 00 
		$a_80_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  01 00 
		$a_80_9 = {50 69 63 74 75 72 65 45 64 69 74 6f 72 } //PictureEditor  00 00 
	condition:
		any of ($a_*)
 
}