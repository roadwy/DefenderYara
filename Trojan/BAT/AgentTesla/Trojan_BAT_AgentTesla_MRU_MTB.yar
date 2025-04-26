
rule Trojan_BAT_AgentTesla_MRU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {55 6e 6d 61 6e 61 67 65 64 46 75 6e 63 74 69 6f 6e } //UnmanagedFunction  1
		$a_80_1 = {42 69 74 6d 61 70 } //Bitmap  1
		$a_80_2 = {43 75 72 72 65 6e 74 53 79 73 74 65 6d 54 69 6d 65 5a 6f 6e 65 } //CurrentSystemTimeZone  1
		$a_80_3 = {53 69 67 6e 61 74 75 72 65 44 65 66 6f 72 6d 61 74 74 65 72 2e 49 50 65 72 6d 69 73 73 69 6f 6e } //SignatureDeformatter.IPermission  1
		$a_80_4 = {44 61 74 61 20 53 6f 75 72 63 65 3d 28 6c 6f 63 61 6c 64 62 29 5c 4d 53 53 51 4c 4c 6f 63 61 6c 44 42 3b 49 6e 69 74 69 61 6c 20 43 61 74 61 6c 6f 67 3d 6d 64 6d 73 44 42 3b 49 6e 74 65 67 72 61 74 65 64 20 53 65 63 75 72 69 74 79 3d 54 72 75 65 3b 50 6f 6f 6c 69 6e 67 3d 46 61 6c 73 65 } //Data Source=(localdb)\MSSQLLocalDB;Initial Catalog=mdmsDB;Integrated Security=True;Pooling=False  1
		$a_80_5 = {54 68 72 65 61 64 50 6f 6f 6c } //ThreadPool  1
		$a_80_6 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //ICryptoTransform  1
		$a_80_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  1
		$a_80_8 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //SymmetricAlgorithm  1
		$a_80_9 = {67 65 74 5f 70 61 79 6d 65 6e 74 } //get_payment  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}