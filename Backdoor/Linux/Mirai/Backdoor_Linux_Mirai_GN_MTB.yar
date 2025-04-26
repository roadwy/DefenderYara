
rule Backdoor_Linux_Mirai_GN_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e6 2f 22 4f 07 d0 f4 7f f3 6e 42 2e 51 1e 66 e4 62 1e 03 e5 0b 40 e3 66 0c 7e e3 6f 26 4f f6 6e } //1
		$a_01_1 = {53 61 63 67 13 66 04 d1 e6 2f 43 65 f3 6e 04 e4 e3 6f f6 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}