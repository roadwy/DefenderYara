
rule Trojan_BAT_DarkCloud_RV_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 1d a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 56 00 00 00 0b 00 00 00 29 00 00 00 d9 00 00 00 2a 00 00 00 90 00 00 00 01 00 00 00 21 00 00 00 17 00 00 00 03 00 00 00 07 00 00 00 08 00 00 00 0c 00 00 00 01 00 00 00 06 00 00 00 05 00 00 00 02 00 00 00 02 00 00 00 02 } //1
		$a_81_1 = {50 65 67 53 6f 6c 69 74 61 69 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 PegSolitaire.Properties.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}