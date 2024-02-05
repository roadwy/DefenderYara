
rule Trojan_BAT_Bladabindi_PSQT_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 89 01 00 0a 72 d4 01 00 70 6f a4 01 00 0a 73 a0 01 00 0a 25 6f 9b 01 00 0a 16 6a } //00 00 
	condition:
		any of ($a_*)
 
}