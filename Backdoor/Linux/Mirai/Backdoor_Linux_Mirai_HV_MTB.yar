
rule Backdoor_Linux_Mirai_HV_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 ba 08 00 00 00 48 89 ca 48 63 ff b8 0e 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 ?? ?? e8 5d 02 00 00 89 da 48 83 cb ff f7 da 89 10 } //1
		$a_03_1 = {53 b8 c9 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 76 ?? e8 34 02 00 00 89 da 48 83 cb ff f7 da 89 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}