
rule Trojan_Linux_Meterpreter_C_MTB{
	meta:
		description = "Trojan:Linux/Meterpreter.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 31 c9 48 81 e9 ef ff ff ff 48 8d 05 ef ff ff ff 48 bb } //00 00 
	condition:
		any of ($a_*)
 
}