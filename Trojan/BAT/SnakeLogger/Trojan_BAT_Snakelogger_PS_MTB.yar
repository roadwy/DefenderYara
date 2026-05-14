
rule Trojan_BAT_Snakelogger_PS_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 02 03 04 06 07 05 0e 04 0e 05 23 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 00 00 06 17 58 0a 06 02 6f ?? ?? ?? 0a 2f 0b 03 6f ?? ?? ?? 0a 04 fe 04 2b 01 16 0c 08 } //10
		$a_01_1 = {74 78 74 44 6f 6b 74 6f 72 52 65 50 61 73 73 77 6f 72 64 } //1 txtDoktorRePassword
		$a_01_2 = {50 68 61 72 6d 61 63 79 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 PharmacyProject.Properties.Resources
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}