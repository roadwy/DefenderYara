
rule Trojan_BAT_Vimditator_SL_MTB{
	meta:
		description = "Trojan:BAT/Vimditator.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 ad 00 00 70 6f 2a 00 00 0a 10 00 dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Vimditator_SL_MTB_2{
	meta:
		description = "Trojan:BAT/Vimditator.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d 0b 2b 0b 72 61 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 1f 00 00 0a 2b f2 0a 2b f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}