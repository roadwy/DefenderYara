
rule Backdoor_BAT_Remcos_ARA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 18 58 1f 0a 58 1f 0c 59 7e ?? ?? ?? 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1f 0b 58 1f 0d 59 91 61 28 ?? ?? ?? 06 02 08 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 59 02 8e 69 5d 91 59 20 ?? ?? ?? 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 9a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}