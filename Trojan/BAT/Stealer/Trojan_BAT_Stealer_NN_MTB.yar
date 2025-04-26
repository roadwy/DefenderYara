
rule Trojan_BAT_Stealer_NN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 91 0d 08 1f 09 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 ?? ?? ?? ?? ?? b4 9c 08 17 d6 0c 08 07 31 dc } //5
		$a_03_1 = {03 6e 60 02 ?? ?? ?? ?? ?? 66 03 66 d2 6e 60 5f b7 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}