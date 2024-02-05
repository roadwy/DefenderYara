
rule Trojan_Linux_Meterpreter_B_MTB{
	meta:
		description = "Trojan:Linux/Meterpreter.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 0c 5e 56 31 1e ad 01 c3 85 c0 75 f7 c3 e8 ef ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}