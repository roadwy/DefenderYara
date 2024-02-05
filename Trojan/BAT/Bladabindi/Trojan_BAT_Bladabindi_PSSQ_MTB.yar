
rule Trojan_BAT_Bladabindi_PSSQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 28 ba 00 00 0a 03 28 ac 00 00 0a 6f af 00 00 0a 0a 2b 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}