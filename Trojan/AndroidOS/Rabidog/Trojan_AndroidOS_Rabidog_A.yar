
rule Trojan_AndroidOS_Rabidog_A{
	meta:
		description = "Trojan:AndroidOS/Rabidog.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 20 74 61 6b 65 20 70 6c 65 61 73 75 72 65 20 69 6e 20 68 75 72 74 69 6e 67 20 73 6d 61 6c 6c 20 61 6e 69 6d 61 6c 73 2c } //1 I take pleasure in hurting small animals,
		$a_01_1 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d } //1 contact_id =
		$a_01_2 = {2f 64 6f 67 62 69 74 65 2f 52 61 62 69 65 73 } //1 /dogbite/Rabies
		$a_01_3 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //1 has_phone_number
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}