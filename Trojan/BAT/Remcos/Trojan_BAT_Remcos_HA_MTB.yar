
rule Trojan_BAT_Remcos_HA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 [0-05] 2e 50 72 6f 70 65 72 74 69 65 73 } //1
		$a_81_1 = {44 78 6f 77 6e 78 6c 6f 78 61 64 44 78 61 74 78 78 61 78 } //1 DxownxloxadDxatxxax
		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}