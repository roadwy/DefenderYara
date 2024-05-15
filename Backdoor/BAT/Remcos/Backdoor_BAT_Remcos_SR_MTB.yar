
rule Backdoor_BAT_Remcos_SR_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 04 00 00 0a 72 01 00 00 70 28 05 00 00 0a 0b 07 8e 69 20 00 04 00 00 2e e6 } //00 00 
	condition:
		any of ($a_*)
 
}