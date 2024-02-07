
rule Trojan_BAT_AgentTesla_AUX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {09 17 d6 0d 17 0a 90 01 05 07 17 d6 0b 1d 0a 2b 90 01 01 02 11 90 01 06 26 1e 0a 2b 90 01 01 11 90 01 06 13 90 01 01 1c 0a 2b 90 01 01 08 17 d6 0c 1b 0a 2b 90 01 01 08 16 fe 02 16 fe 01 13 90 01 01 11 90 01 01 2c 90 00 } //01 00 
		$a_80_1 = {47 65 74 50 69 78 65 6c } //GetPixel  01 00 
		$a_80_2 = {54 6f 57 69 6e 33 32 } //ToWin32  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AUX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //SmartExtensions  01 00 
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 e2 80 8e } //FromBase64String‎  01 00 
		$a_80_2 = {47 65 74 43 68 61 72 } //GetChar  01 00 
		$a_80_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //GetTypeFromHandle  01 00 
		$a_00_4 = {0d 59 0d 59 36 52 0d 59 0d 59 36 52 0d 59 0d 59 } //01 00  复复制复复制复复
		$a_80_5 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_6 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_7 = {53 6d 61 72 74 46 6f 72 6d 61 74 } //SmartFormat  01 00 
		$a_80_8 = {46 6c 6f 72 61 } //Flora  01 00 
		$a_80_9 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_10 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //OffsetMarshaler  01 00 
		$a_80_11 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //ReturnMessage  00 00 
	condition:
		any of ($a_*)
 
}