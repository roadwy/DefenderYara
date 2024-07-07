
rule Backdoor_BAT_Remcos_ABZ_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 16 73 06 90 01 02 0a 73 07 90 01 02 0a 0d 00 09 08 6f 08 90 01 02 0a 00 00 de 0b 09 2c 07 09 6f 09 90 01 02 0a 00 dc 08 6f 0a 90 01 02 0a 13 04 de 16 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}