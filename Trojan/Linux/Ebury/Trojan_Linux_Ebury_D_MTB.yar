
rule Trojan_Linux_Ebury_D_MTB{
	meta:
		description = "Trojan:Linux/Ebury.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f9 2f 41 89 e9 44 0f 45 cb 44 88 c1 c1 e1 04 41 88 cb 44 88 c9 c0 e9 02 41 88 cc 8a 4e 03 45 09 dc 80 f9 3d } //1
		$a_01_1 = {41 83 e0 03 ff c0 42 32 4c 04 f0 88 cb 83 e1 0f c0 eb 04 44 0f b6 c3 46 8a 84 02 f2 0d 00 00 44 88 06 8a 8c 0a f2 0d 00 00 88 4e 01 48 83 c6 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}