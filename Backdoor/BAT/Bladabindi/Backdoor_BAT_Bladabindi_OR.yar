
rule Backdoor_BAT_Bladabindi_OR{
	meta:
		description = "Backdoor:BAT/Bladabindi.OR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 00 6e 00 69 00 6f 00 70 00 79 00 72 00 74 00 6e 00 45 00 } //1 tniopyrtnE
		$a_00_1 = {65 00 6b 00 6f 00 76 00 6e 00 49 00 } //1 ekovnI
		$a_02_2 = {17 17 8d 18 00 00 01 25 16 fe 0c 87 03 00 00 a2 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 8d 03 00 00 fe 0c 8d 03 00 00 28 ?? ?? ?? ?? fe 0c 89 03 00 00 28 ?? ?? ?? ?? 18 16 8d 18 00 00 01 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 8e 03 00 00 fe 0c 8e 03 00 00 28 ?? ?? ?? ?? fe 0c 8a 03 00 00 28 ?? ?? ?? ?? 17 18 8d 18 00 00 01 28 ?? ?? ?? ?? 28 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=4
 
}