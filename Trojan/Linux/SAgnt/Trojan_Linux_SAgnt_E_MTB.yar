
rule Trojan_Linux_SAgnt_E_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {48 89 e5 bf 00 00 00 00 b8 00 00 00 00 e8 e0 fe ff ff bf 00 00 00 00 b8 00 00 00 00 e8 c1 fe ff ff ba 00 00 00 00 be 90 06 40 00 bf 95 06 40 00 b8 00 00 00 00 e8 c8 fe ff ff } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}