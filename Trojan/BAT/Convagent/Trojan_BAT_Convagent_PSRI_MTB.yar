
rule Trojan_BAT_Convagent_PSRI_MTB{
	meta:
		description = "Trojan:BAT/Convagent.PSRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 28 04 00 00 0a 2a } //01 00 
		$a_01_1 = {67 77 67 61 6c 67 30 6b } //00 00 
	condition:
		any of ($a_*)
 
}