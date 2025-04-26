
rule Backdoor_BAT_Remcos_SKK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 07 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 09 09 11 05 07 11 05 91 11 04 11 09 95 61 28 a7 00 00 0a 9c 11 05 17 58 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}