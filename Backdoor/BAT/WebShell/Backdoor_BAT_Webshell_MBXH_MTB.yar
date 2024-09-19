
rule Backdoor_BAT_Webshell_MBXH_MTB{
	meta:
		description = "Backdoor:BAT/Webshell.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 00 65 00 79 00 00 21 63 00 37 00 30 00 66 00 64 00 34 00 32 00 36 00 30 00 63 00 39 00 65 00 62 00 39 00 30 00 62 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}