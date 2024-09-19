
rule Trojan_Win32_WarzoneRAT_DG_MTB{
	meta:
		description = "Trojan:Win32/WarzoneRAT.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 34 39 34 } //50 $cc7fad03-816e-432c-9b92-001f2d378494
		$a_81_1 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //5 Base64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //5 CreateInstance
		$a_81_3 = {49 6e 76 6f 6b 65 } //5 Invoke
		$a_81_4 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 } //1 get_encrypted
		$a_81_5 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=66
 
}