
rule Trojan_BAT_AveMaria_NRA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 7e 02 00 00 04 06 7e 90 01 03 04 06 91 20 90 01 03 00 59 d2 9c 00 06 17 58 0a 06 7e 90 01 03 04 8e 69 fe 04 0b 07 2d d7 90 00 } //5
		$a_01_1 = {43 6f 6e 74 72 6f 6c 57 69 6e 2e 50 72 6f 67 72 65 73 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ControlWin.Progress.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}