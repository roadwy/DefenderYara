
rule Trojan_Linux_SAgnt_H_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {71 0c 0e 1b 94 a1 c1 a7 85 fb e8 48 60 88 de 98 58 8c 1b b4 5d 97 bc 3e f4 71 44 77 bf 67 92 53 56 a9 6d 60 13 c7 0d d4 1a 12 b0 60 a7 f8 cb ba } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}