
rule HackTool_BAT_Uflooder_A_bit{
	meta:
		description = "HackTool:BAT/Uflooder.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 44 50 5f 46 6c 6f 6f 64 } //1 UDP_Flood
		$a_01_1 = {53 00 74 00 61 00 72 00 74 00 20 00 41 00 74 00 74 00 61 00 63 00 6b 00 } //1 Start Attack
		$a_01_2 = {45 00 74 00 65 00 72 00 6e 00 61 00 6c 00 73 00 20 00 55 00 44 00 50 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 } //1 Eternals UDP Flood
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}