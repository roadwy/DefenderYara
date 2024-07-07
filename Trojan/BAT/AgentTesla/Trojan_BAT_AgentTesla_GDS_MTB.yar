
rule Trojan_BAT_AgentTesla_GDS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 63 37 39 35 33 34 33 35 39 34 39 33 61 39 38 37 35 33 35 65 36 38 31 61 35 38 31 65 65 35 38 64 } //1 cc79534359493a987535e681a581ee58d
		$a_01_1 = {63 61 30 32 38 62 37 36 39 39 66 38 34 64 31 61 32 37 61 63 30 63 38 64 34 34 33 38 65 64 31 33 31 } //1 ca028b7699f84d1a27ac0c8d4438ed131
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}