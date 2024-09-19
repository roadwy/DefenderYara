
rule Backdoor_BAT_Remcos_SDK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}