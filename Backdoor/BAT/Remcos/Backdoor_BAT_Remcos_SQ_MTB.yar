
rule Backdoor_BAT_Remcos_SQ_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 11 00 00 0a 72 d7 00 00 70 28 12 00 00 0a 13 04 11 04 28 13 00 00 0a dd 06 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}