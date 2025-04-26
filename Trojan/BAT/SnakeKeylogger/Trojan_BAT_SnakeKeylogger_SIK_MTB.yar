
rule Trojan_BAT_SnakeKeylogger_SIK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 16 13 07 38 9c 00 00 00 00 07 11 06 11 07 6f 5d 00 00 0a 13 08 09 12 08 28 5e 00 00 0a 6f 5f 00 00 0a 00 09 12 08 28 60 00 00 0a 6f 5f 00 00 0a 00 09 12 08 28 61 00 00 0a 6f 5f 00 00 0a 00 20 00 1e 01 00 13 09 08 6f 62 00 00 0a } //1
		$a_81_1 = {44 65 6c 65 74 65 54 65 78 74 62 6f 78 2e 4d 61 69 6e 46 6f 72 6d 73 2e 72 65 73 6f 75 72 63 65 73 } //1 DeleteTextbox.MainForms.resources
		$a_81_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_3 = {54 65 78 74 42 6f 78 4d 61 73 6b 49 6e 70 75 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 TextBoxMaskInput.Properties.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}