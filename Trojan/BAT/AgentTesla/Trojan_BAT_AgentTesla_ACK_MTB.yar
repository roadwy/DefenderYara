
rule Trojan_BAT_AgentTesla_ACK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 19 8d 5e 00 00 01 25 16 12 02 28 59 00 00 0a 9c 25 17 12 02 28 5a 00 00 0a 9c 25 18 12 02 28 5b 00 00 0a 9c 13 06 19 } //2
		$a_81_1 = {43 72 75 64 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 CrudApplication.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_ACK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 6c 6f 67 73 5c 52 65 63 6f 6c 65 63 74 6f 72 44 6f 63 75 6d 65 6e 74 6f 73 } //1 C:\logs\RecolectorDocumentos
		$a_81_1 = {53 61 78 53 65 74 74 69 6e 67 73 } //1 SaxSettings
		$a_81_2 = {52 65 67 69 6d 65 6e 2d 54 69 70 6f 2d 4f 70 65 72 61 63 69 6f 6e 2d 43 76 65 50 65 64 69 6d 65 6e 74 6f 20 49 6e 76 } //1 Regimen-Tipo-Operacion-CvePedimento Inv
		$a_81_3 = {53 6f 6c 69 75 6d 20 46 6f 72 77 61 72 64 69 6e 67 20 49 6e 63 } //1 Solium Forwarding Inc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}