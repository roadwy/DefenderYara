
rule Backdoor_BAT_Remcos_SCK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 09 8e 69 5d 09 8e 69 58 09 8e 69 5d 13 07 09 11 07 91 13 08 11 06 08 5d 08 58 08 5d 13 09 07 11 09 91 11 08 61 13 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}