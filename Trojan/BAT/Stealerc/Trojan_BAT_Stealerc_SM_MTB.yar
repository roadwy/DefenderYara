
rule Trojan_BAT_Stealerc_SM_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 08 03 08 91 05 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Stealerc_SM_MTB_2{
	meta:
		description = "Trojan:BAT/Stealerc.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 19 8d 8f 00 00 01 25 16 12 02 28 bd 00 00 0a 9c 25 17 12 02 28 be 00 00 0a 9c 25 18 12 02 28 bf 00 00 0a 9c } //2
		$a_81_1 = {41 67 72 6f 46 61 72 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 AgroFarm.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}