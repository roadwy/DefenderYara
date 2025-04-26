
rule Trojan_Linux_Bew_A_MTB{
	meta:
		description = "Trojan:Linux/Bew.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 59 89 e0 51 8d 74 88 04 56 50 51 89 35 70 e0 04 08 ad 85 c0 75 fb } //1
		$a_00_1 = {74 6d 70 64 38 31 39 69 73 31 33 } //1 tmpd819is13
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}