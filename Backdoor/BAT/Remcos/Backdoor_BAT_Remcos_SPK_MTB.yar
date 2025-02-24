
rule Backdoor_BAT_Remcos_SPK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 1f 10 5d 04 07 d8 b5 9d 02 03 04 07 05 28 69 00 00 06 07 17 d6 0b 07 02 6f bf 00 00 0a 2f 09 03 6f bc 00 00 0a 05 32 d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}