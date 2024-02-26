
rule Trojan_BAT_Bladabindi_PTCJ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 20 00 00 06 6f 4e 00 00 0a 02 72 fb 00 00 70 6f 45 00 00 0a 02 72 fb 00 00 70 6f 4f 00 00 0a 02 16 6f 50 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}