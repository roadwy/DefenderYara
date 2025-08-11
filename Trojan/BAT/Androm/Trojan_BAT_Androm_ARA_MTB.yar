
rule Trojan_BAT_Androm_ARA_MTB{
	meta:
		description = "Trojan:BAT/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 08 03 8e 69 5d 94 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 00 08 17 59 0c 08 16 fe 04 16 fe 01 13 05 11 05 2d d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Androm_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 11 07 11 06 11 07 91 1b 59 20 00 01 00 00 58 20 ?? ?? ?? ?? 5a 20 00 01 00 00 5d d2 9c 11 06 11 07 8f ?? ?? ?? ?? 25 47 03 09 58 20 00 01 00 00 5d d2 61 d2 52 00 11 07 17 58 13 07 11 07 11 06 8e 69 fe 04 13 08 11 08 2d b3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Androm_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Androm.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 6e 69 74 43 6f 6e 76 65 72 74 65 72 2e 55 6e 69 74 43 6f 6e 76 65 72 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //2 UnitConverter.UnitConverter.resources
		$a_01_1 = {55 6e 69 74 43 6f 6e 76 65 72 74 65 72 31 2e 4e 6f 64 65 73 43 6f 6e 74 72 6f 6c 2e 72 65 73 6f 75 72 63 65 73 } //2 UnitConverter1.NodesControl.resources
		$a_01_2 = {55 6e 69 74 43 6f 6e 76 65 72 74 65 72 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 UnitConverter1.Properties.Resources
		$a_01_3 = {6b 65 79 45 76 65 6e 74 41 72 67 73 } //1 keyEventArgs
		$a_01_4 = {4e 6f 64 65 73 43 6f 6e 74 72 6f 6c 5f 4d 6f 75 73 65 4d 6f 76 65 } //1 NodesControl_MouseMove
		$a_01_5 = {61 64 64 5f 4d 6f 75 73 65 43 6c 69 63 6b } //1 add_MouseClick
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}