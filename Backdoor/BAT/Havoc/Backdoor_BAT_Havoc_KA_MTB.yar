
rule Backdoor_BAT_Havoc_KA_MTB{
	meta:
		description = "Backdoor:BAT/Havoc.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 09 6f 03 00 00 0a 0b 06 1b 62 06 58 07 d2 6e 58 0a 09 17 58 0d 09 08 } //05 00 
		$a_01_1 = {03 50 08 06 07 d3 58 47 9c 07 17 58 0b 08 17 58 0c 08 04 05 58 } //00 00 
	condition:
		any of ($a_*)
 
}