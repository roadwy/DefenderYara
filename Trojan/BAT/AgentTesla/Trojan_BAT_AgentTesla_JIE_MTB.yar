
rule Trojan_BAT_AgentTesla_JIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1a 02 72 ?? ?? ?? 70 06 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 06 17 58 0a 06 20 ?? ?? ?? 00 32 de } //10
		$a_81_1 = {35 65 31 35 64 33 39 32 2d 33 33 33 31 2d 34 31 37 35 2d 62 30 34 65 2d 62 66 33 64 65 62 61 37 37 37 36 36 } //1 5e15d392-3331-4175-b04e-bf3deba77766
		$a_81_2 = {78 73 74 6f 70 70 61 72 74 79 6b 65 65 70 74 6f 67 65 74 68 65 72 } //1 xstoppartykeeptogether
		$a_81_3 = {68 6f 73 74 6d 69 67 72 61 74 69 6f 6e 5f 73 74 61 72 74 } //1 hostmigration_start
		$a_81_4 = {6b 69 6c 6c 73 65 72 76 65 72 } //1 killserver
		$a_81_5 = {42 6c 61 63 6b 4f 70 73 43 6f 6c 64 57 61 72 } //1 BlackOpsColdWar
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}