
rule Trojan_BAT_AgentTesla_APD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 16 03 a2 25 13 04 14 14 17 90 01 05 25 16 17 9c 25 13 05 90 01 05 11 05 16 91 2c 03 17 2b 03 16 2b 00 2d 02 2b 90 00 } //01 00 
		$a_80_1 = {47 65 74 50 69 78 65 6c } //GetPixel  01 00 
		$a_80_2 = {54 6f 57 69 6e 33 32 } //ToWin32  01 00 
		$a_80_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } //SimpleUI.MDI  00 00 
	condition:
		any of ($a_*)
 
}