
rule Trojan_BAT_Vidar_NVB_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 } //5
		$a_01_1 = {53 6e 61 6b 65 73 41 6e 64 4c 61 64 64 65 72 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 SnakesAndLadders.Properties.Resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}