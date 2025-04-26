
rule Trojan_BAT_AveMariaRAT_D_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 08 04 8e 69 5d 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 04 08 1d 58 1c 59 04 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}