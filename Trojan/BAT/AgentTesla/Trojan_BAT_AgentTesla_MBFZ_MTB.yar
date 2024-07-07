
rule Trojan_BAT_AgentTesla_MBFZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 39 62 32 34 34 36 64 61 2d 63 37 39 64 2d 34 33 30 61 2d 62 31 62 30 2d 64 30 31 63 30 32 61 35 38 65 63 31 } //10 $9b2446da-c79d-430a-b1b0-d01c02a58ec1
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}