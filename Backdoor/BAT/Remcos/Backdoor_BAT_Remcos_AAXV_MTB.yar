
rule Backdoor_BAT_Remcos_AAXV_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AAXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 8e 69 5d 18 58 1b 58 1d 59 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? 00 00 0a 04 08 20 89 10 00 00 58 20 88 10 00 00 59 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 1b 2c 89 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}