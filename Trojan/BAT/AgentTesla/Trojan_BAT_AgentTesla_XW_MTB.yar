
rule Trojan_BAT_AgentTesla_XW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 63 66 65 64 64 31 36 34 2d 30 30 33 65 2d 34 37 31 34 2d 62 39 64 38 2d 36 38 65 65 39 66 36 30 39 62 65 61 } //10 $cfedd164-003e-4714-b9d8-68ee9f609bea
		$a_01_1 = {50 61 72 73 65 46 61 69 6c 75 72 65 } //1 ParseFailure
		$a_01_2 = {4e 65 78 74 41 63 74 69 76 61 74 6f 72 } //1 NextActivator
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}