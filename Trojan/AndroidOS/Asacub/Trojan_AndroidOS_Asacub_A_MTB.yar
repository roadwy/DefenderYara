
rule Trojan_AndroidOS_Asacub_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Asacub.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {03 af 4d f8 04 8d 04 46 13 48 90 46 22 68 78 44 05 68 20 46 92 69 55 f8 21 10 90 47 06 46 20 68 55 f8 28 20 31 46 d5 f8 e4 36 d0 f8 40 52 20 46 a8 47 02 46 20 68 31 46 d0 f8 58 32 20 46 98 47 05 46 20 68 31 46 c2 6d 20 46 90 47 28 46 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}