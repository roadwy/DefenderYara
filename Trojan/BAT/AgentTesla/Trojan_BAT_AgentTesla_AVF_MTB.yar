
rule Trojan_BAT_AgentTesla_AVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {07 17 d6 0b 17 90 01 07 00 11 90 01 01 17 d6 13 90 01 01 1d 13 90 01 01 2b 90 01 01 00 02 09 28 90 01 03 06 26 1e 13 90 01 01 2b 90 01 01 00 11 90 01 01 28 90 01 03 0a 0a 1c 13 90 01 01 2b 90 00 } //01 00 
		$a_80_1 = {54 6f 57 69 6e 33 32 } //ToWin32  01 00 
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  00 00 
	condition:
		any of ($a_*)
 
}