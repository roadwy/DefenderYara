
rule Backdoor_Linux_Xdr33_A_MTB{
	meta:
		description = "Backdoor:Linux/Xdr33.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c9 ff 31 c0 bf e0 2f 0e 08 f2 ae f7 d1 80 b9 df 2f 0e 08 2f 74 ?? 57 57 68 a7 1c 0c 08 68 e0 2f 0e 08 e8 ?? ?? ?? ?? 83 c4 10 } //1
		$a_03_1 = {50 50 8d 85 b8 fd ff ff 50 ff 35 d8 78 0f 08 e8 ?? ?? ?? ?? 83 c4 10 85 c0 74 ?? 83 ec 0c 68 ad 41 0b 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}