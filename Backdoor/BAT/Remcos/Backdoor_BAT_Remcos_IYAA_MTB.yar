
rule Backdoor_BAT_Remcos_IYAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.IYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 ?? 08 20 0e 02 00 00 58 20 0d 02 00 00 59 1b 59 1b 58 ?? 8e 69 5d 1f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}