
rule Trojan_Linux_SAgnt_F_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {48 8d 35 cc 07 00 00 48 8d 3d c7 07 00 00 ba 01 00 00 00 e8 59 f7 ff ff 48 8b 44 24 48 48 8d bc 24 30 02 00 00 31 d2 48 8b 30 31 c0 e8 a0 f5 ff ff 89 c7 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}