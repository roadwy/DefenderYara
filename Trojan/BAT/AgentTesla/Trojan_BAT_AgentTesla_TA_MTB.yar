
rule Trojan_BAT_AgentTesla_TA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0c 08 20 90 01 04 6f 90 01 04 08 20 90 01 04 6f 90 01 04 28 90 01 04 72 90 01 03 70 6f 90 01 03 0a 06 20 90 01 04 73 90 01 04 0d 08 09 08 6f 90 01 03 0a 1e 5b 6f 90 01 04 6f 90 01 03 0a 08 09 08 6f 90 01 04 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 17 6f 90 01 04 07 08 6f 90 01 04 17 73 90 01 04 13 04 11 04 02 16 02 8e 69 6f 90 01 04 11 04 90 00 } //01 00 
		$a_80_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //RijndaelManaged  01 00 
		$a_80_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //ClassLibrary  00 00 
	condition:
		any of ($a_*)
 
}