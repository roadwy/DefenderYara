
rule Ransom_Linux_LockBit_I_MTB{
	meta:
		description = "Ransom:Linux/LockBit.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 1a f2 ff ff 31 db b8 78 b9 65 00 b9 78 b9 65 00 48 29 c1 48 89 c8 48 c1 f8 3f 48 c1 e8 3d 48 01 c8 48 c1 f8 03 74 48 b8 78 b9 65 00 b9 78 b9 65 00 48 29 c1 49 89 cc 49 c1 fc 3f 49 c1 ec 3d 49 01 cc 49 c1 fc 03 0f 1f 84 00 00 00 00 00 } //1
		$a_01_1 = {48 83 c4 08 5b 5d 41 5c 41 5d c3 e8 66 ee ff ff 83 38 23 74 cb 90 e8 5b ee ff ff 83 38 23 74 c0 48 89 d8 eb db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}