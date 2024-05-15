
rule Trojan_BAT_AgentTesla_ACK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 6c 6f 67 73 5c 52 65 63 6f 6c 65 63 74 6f 72 44 6f 63 75 6d 65 6e 74 6f 73 } //01 00  C:\logs\RecolectorDocumentos
		$a_81_1 = {53 61 78 53 65 74 74 69 6e 67 73 } //01 00  SaxSettings
		$a_81_2 = {52 65 67 69 6d 65 6e 2d 54 69 70 6f 2d 4f 70 65 72 61 63 69 6f 6e 2d 43 76 65 50 65 64 69 6d 65 6e 74 6f 20 49 6e 76 } //01 00  Regimen-Tipo-Operacion-CvePedimento Inv
		$a_81_3 = {53 6f 6c 69 75 6d 20 46 6f 72 77 61 72 64 69 6e 67 20 49 6e 63 } //00 00  Solium Forwarding Inc
	condition:
		any of ($a_*)
 
}