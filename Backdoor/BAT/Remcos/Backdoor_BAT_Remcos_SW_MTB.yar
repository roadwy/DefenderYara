
rule Backdoor_BAT_Remcos_SW_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 8e 69 5d 1f 66 59 1f 66 58 02 08 02 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 1f 16 58 1f 16 59 91 61 02 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}