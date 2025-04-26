
rule Backdoor_BAT_Remcos_AIPA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AIPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 2c 3c 09 14 72 3f 27 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 01 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? 01 00 0a 13 0e 11 0e 2d c4 } //5
		$a_01_1 = {4c 00 20 00 6f 00 20 00 61 00 20 00 64 00 } //2 L o a d
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}