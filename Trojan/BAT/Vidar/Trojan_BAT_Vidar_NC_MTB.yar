
rule Trojan_BAT_Vidar_NC_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 } //3
		$a_81_1 = {31 33 65 61 66 66 39 65 2d 34 65 62 61 2d 34 65 30 62 2d 61 61 30 62 2d 66 35 61 61 33 65 33 33 30 32 38 31 } //2 13eaff9e-4eba-4e0b-aa0b-f5aa3e330281
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*2) >=5
 
}