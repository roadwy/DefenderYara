
rule Backdoor_BAT_Remcos_ADJA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ADJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 59 91 61 ?? 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 ?? 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}