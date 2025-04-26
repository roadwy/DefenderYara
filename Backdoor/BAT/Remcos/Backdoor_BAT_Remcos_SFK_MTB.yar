
rule Backdoor_BAT_Remcos_SFK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 0a 28 74 00 00 06 0a 06 0b de 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}