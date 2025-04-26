
rule Trojan_BAT_Taskun_SP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 1f 0a 5a 6f 6d 00 00 0a 26 04 07 08 91 6f 6e 00 00 0a 08 17 58 0c 08 03 32 e4 } //2
		$a_81_1 = {4d 61 74 65 72 69 61 6c 57 69 6e 66 6f 72 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 MaterialWinforms.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}