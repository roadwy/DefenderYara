
rule Trojan_BAT_Vidar_NAE_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 16 9a 26 16 2d f9 00 28 90 01 01 00 00 06 20 90 01 01 00 00 00 28 90 01 01 00 00 06 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 0b 07 74 90 01 01 00 00 1b 90 00 } //5
		$a_01_1 = {6e 69 64 65 72 6c 61 6e 64 73 64 6c 6c 5f 63 6c 61 6d 65 75 70 } //1 niderlandsdll_clameup
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}