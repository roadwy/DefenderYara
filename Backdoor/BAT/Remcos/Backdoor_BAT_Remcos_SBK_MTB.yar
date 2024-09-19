
rule Backdoor_BAT_Remcos_SBK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 08 5d 08 58 08 5d 13 0a 07 11 0a 91 13 0b 11 0b 11 07 61 13 0c 11 0c 11 09 59 20 00 02 00 00 58 13 0d 11 0d 20 00 01 00 00 5d 20 00 04 00 00 58 13 0e 11 0e 20 00 02 00 00 5d 13 0f 16 13 1b 2b 1b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}