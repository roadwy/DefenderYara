
rule Trojan_BAT_Vidar_NDA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 03 a2 25 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0c 17 28 } //5
		$a_01_1 = {45 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Es.Resources.resources
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsApp1.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}