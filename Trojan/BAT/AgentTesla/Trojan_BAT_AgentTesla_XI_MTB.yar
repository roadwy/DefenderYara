
rule Trojan_BAT_AgentTesla_XI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {31 31 33 2e 32 31 32 2e 38 38 2e 31 32 36 } //113.212.88.126  01 00 
		$a_80_1 = {31 32 37 2e 30 2e 30 2e 31 } //127.0.0.1  01 00 
		$a_01_2 = {2e 70 64 62 } //01 00 
		$a_80_3 = {52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 } //Roaming\Microsoft\Windows\system32  01 00 
		$a_80_4 = {73 79 73 74 65 6d 2e 62 69 6e } //system.bin  01 00 
		$a_01_5 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //01 00 
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}