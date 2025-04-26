
rule Trojan_AndroidOS_Piom_R{
	meta:
		description = "Trojan:AndroidOS/Piom.R,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {37 45 35 77 58 54 59 4f 41 38 72 41 2b 7a 5a 68 35 51 6c 6a 56 4e 72 72 41 50 49 } //1 7E5wXTYOA8rA+zZh5QljVNrrAPI
		$a_01_1 = {63 6f 6d 43 6c 61 73 73 } //1 comClass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}