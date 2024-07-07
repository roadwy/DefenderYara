
rule Trojan_BAT_Formbook_RDP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6e 69 6d 61 6c 5f 49 64 65 6e 74 69 66 79 32 } //1 Animal_Identify2
		$a_01_1 = {43 6f 6d 70 61 74 69 62 69 6c 69 74 79 20 44 61 74 61 62 61 73 65 } //1 Compatibility Database
		$a_01_2 = {58 65 6d 5f 68 69 6e 68 5f 66 6f 72 6d } //1 Xem_hinh_form
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}