
rule Trojan_BAT_AgentTesla_TC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8e 69 17 da 0c 16 0d 90 01 01 13 05 2b 90 01 01 06 90 01 05 09 06 90 01 05 09 91 7e 90 01 04 7e 90 01 04 6f 90 01 04 74 90 01 04 07 09 28 90 01 04 9c 90 01 01 13 05 38 90 01 01 ff ff ff 09 17 d6 0d 90 01 01 13 05 38 90 01 01 ff ff ff 09 08 90 00 } //0a 00 
		$a_02_1 = {8e 69 17 da 0c 16 90 01 01 2b 90 01 01 06 09 06 09 91 7e 90 01 04 7e 90 01 04 6f 90 01 04 74 90 01 04 07 09 28 90 01 04 9c 09 17 d6 0d 09 08 31 d7 90 00 } //01 00 
		$a_80_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  01 00 
		$a_80_3 = {73 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //set_ConnectionString  01 00 
		$a_80_4 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  01 00 
		$a_80_5 = {43 6f 72 72 75 70 74 4c 6f 61 64 } //CorruptLoad  01 00 
		$a_80_6 = {57 72 69 74 65 52 65 73 50 61 73 73 77 6f 72 64 } //WriteResPassword  01 00 
		$a_80_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}