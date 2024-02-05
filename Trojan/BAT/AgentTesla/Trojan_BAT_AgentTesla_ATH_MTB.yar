
rule Trojan_BAT_AgentTesla_ATH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ATH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {58 41 53 58 41 58 } //XASXAX  01 00 
		$a_80_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //ToCharArray  01 00 
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 e2 80 8e } //FromBase64CharArray‎  01 00 
		$a_80_3 = {47 65 74 43 68 61 72 } //GetChar  01 00 
		$a_80_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //GetTypeFromHandle  01 00 
		$a_80_5 = {73 73 73 61 73 53 41 44 41 53 44 41 44 41 44 73 73 } //sssasSADASDADADss  01 00 
		$a_80_6 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_7 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_8 = {53 6d 61 72 74 46 6f 72 6d 61 74 } //SmartFormat  01 00 
		$a_80_9 = {46 6c 6f 72 61 } //Flora  01 00 
		$a_80_10 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_11 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //OffsetMarshaler  01 00 
		$a_80_12 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //ReturnMessage  00 00 
	condition:
		any of ($a_*)
 
}