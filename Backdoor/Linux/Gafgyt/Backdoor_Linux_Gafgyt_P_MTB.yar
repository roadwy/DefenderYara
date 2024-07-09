
rule Backdoor_Linux_Gafgyt_P_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {e6 2f 22 4f 07 d0 f0 7f f3 6e 42 2e 51 1e 09 e4 62 1e 73 1e ?? ?? e3 65 10 7e e3 6f 26 4f f6 6e } //1
		$a_03_1 = {4e 56 ff f0 20 2e 00 08 2d 40 ff f0 20 2e 00 0c 2d 40 ff f4 2d 6e 00 10 ff f8 20 2e 00 14 2d 40 ff fc 41 ee ff f0 2f 08 48 78 00 09 61 ff 00 00 0e ?? 50 8f 4e 5e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}