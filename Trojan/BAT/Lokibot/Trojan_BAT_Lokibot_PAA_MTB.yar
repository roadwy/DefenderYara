
rule Trojan_BAT_Lokibot_PAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 00 06 01 00 8d } //1
		$a_81_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_81_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_3 = {47 61 6d 65 5f 4f 66 5f 4c 69 66 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Game_Of_Life.Properties.Resources.resources
		$a_81_4 = {38 36 61 66 38 66 63 64 2d 30 66 31 37 2d 34 36 34 65 2d 62 32 63 66 2d 65 35 63 30 61 38 64 30 36 64 33 64 } //1 86af8fcd-0f17-464e-b2cf-e5c0a8d06d3d
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}