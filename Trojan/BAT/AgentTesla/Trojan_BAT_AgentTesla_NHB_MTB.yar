
rule Trojan_BAT_AgentTesla_NHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 32 05 00 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a } //5
		$a_01_1 = {4d 47 2e 4f 66 66 69 63 65 2e 44 69 61 67 72 61 6d } //1 MG.Office.Diagram
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NHB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 66 61 73 64 61 73 64 61 64 76 78 66 61 66 64 66 64 73 67 64 66 67 64 66 66 73 64 66 66 66 61 66 67 73 64 64 64 64 64 6f 6b 75 69 6a 6f 75 69 6c 70 6f 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #fasdasdadvxfafdfdsgdfgdffsdfffafgsdddddokuijouilpoddddssaf.dll#
		$a_01_1 = {23 66 61 61 64 61 73 64 73 66 66 67 73 73 61 73 66 64 73 66 64 64 66 73 66 67 64 66 66 6b 6b 6c 76 63 6c 6a 69 67 66 64 64 64 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #faadasdsffgssasfdsfddfsfgdffkklvcljigfdddddddssaf.dll#
		$a_01_2 = {66 61 76 63 78 73 66 64 73 61 64 67 66 67 64 64 61 73 64 66 67 64 66 64 73 73 66 66 66 66 66 66 66 67 73 } //1 favcxsfdsadgfgddasdfgdfdssfffffffgs
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}