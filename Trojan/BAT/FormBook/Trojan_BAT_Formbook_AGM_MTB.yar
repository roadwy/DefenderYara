
rule Trojan_BAT_Formbook_AGM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 36 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 06 11 06 2d bd } //2
		$a_01_1 = {54 00 61 00 73 00 6b 00 31 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Task1Simulation
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}