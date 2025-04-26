
rule Trojan_BAT_AgentTesla_NKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 38 31 38 61 33 33 61 30 2d 33 63 32 61 2d 34 33 66 33 2d 39 65 30 61 2d 61 38 33 39 35 33 34 34 63 65 30 61 } //1 $818a33a0-3c2a-43f3-9e0a-a8395344ce0a
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {74 72 65 76 6e 6f 43 2e 6d 65 74 73 79 53 } //1 trevnoC.metsyS
		$a_81_4 = {67 6e 69 72 74 53 34 36 65 73 61 42 6d 6f 72 46 } //1 gnirtS46esaBmorF
		$a_81_5 = {72 65 62 6d 65 4d 65 6b 6f 76 6e 49 } //1 rebmeMekovnI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}