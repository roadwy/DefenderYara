
rule Trojan_AndroidOS_Asacub_A_xp{
	meta:
		description = "Trojan:AndroidOS/Asacub.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 64 4d 65 74 68 6f 64 45 50 38 5f 6a 6f } //1 idMethodEP8_jo
		$a_00_1 = {20 00 29 00 b0 47 02 00 20 00 29 00 02 f0 } //1
		$a_00_2 = {00 d0 b5 02 af 0c 4c 0d 49 0d 4b a2 42 00 db 19 00 7d 23 dc 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}