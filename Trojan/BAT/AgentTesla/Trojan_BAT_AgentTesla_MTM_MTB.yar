
rule Trojan_BAT_AgentTesla_MTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 6f 6b 65 6e 69 7a 65 72 } //Tokenizer  01 00 
		$a_80_1 = {56 61 72 69 61 6e 74 } //Variant  01 00 
		$a_80_2 = {44 61 74 61 5f 31 } //Data_1  01 00 
		$a_80_3 = {52 6f 75 6e 64 } //Round  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  01 00 
		$a_80_5 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //kernel32.dll  01 00 
		$a_80_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //CheckRemoteDebuggerPresent  01 00 
		$a_80_7 = {58 73 64 54 79 70 65 } //XsdType  01 00 
		$a_80_8 = {67 65 74 5f 53 79 6e 63 } //get_Sync  01 00 
		$a_80_9 = {42 69 74 6d 61 70 } //Bitmap  01 00 
		$a_80_10 = {42 6c 6f 63 6b 43 6f 70 79 } //BlockCopy  00 00 
	condition:
		any of ($a_*)
 
}