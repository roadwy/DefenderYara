
rule Backdoor_BAT_Remcos_ETAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ETAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 07 08 07 8e 69 5d 18 58 1f 0b 58 1f 0d 59 91 61 28 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}