
rule Trojan_BAT_AgentTesla_NXN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {48 5a 56 30 42 47 35 43 48 35 47 52 44 45 47 38 47 35 35 42 37 38 } //1 HZV0BG5CH5GRDEG8G55B78
		$a_81_1 = {4f 45 2e 50 53 } //1 OE.PS
		$a_81_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}