
rule Trojan_Win32_Qakbot_CR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {6d 61 70 74 6f 72 5f 61 6c 6c 6f 63 5f 6d 65 6d 6f 72 79 } //1 maptor_alloc_memory
		$a_01_1 = {6d 61 70 74 6f 72 5f 61 76 6c 74 72 65 65 5f 69 74 65 72 61 74 6f 72 5f 69 73 5f 65 6e 64 } //1 maptor_avltree_iterator_is_end
		$a_01_2 = {6d 61 70 74 6f 72 5f 62 61 73 65 6e 61 6d 65 } //1 maptor_basename
		$a_01_3 = {6d 61 70 74 6f 72 5f 62 6e 6f 64 65 69 64 5f 6e 74 72 69 70 6c 65 73 5f 77 72 69 74 65 } //1 maptor_bnodeid_ntriples_write
		$a_01_4 = {6d 61 70 74 6f 72 5f 64 6f 6d 61 69 6e 5f 67 65 74 5f 6c 61 62 65 6c } //1 maptor_domain_get_label
		$a_01_5 = {6d 61 70 74 6f 72 5f 66 72 65 65 5f 6f 70 74 69 6f 6e 5f 64 65 73 63 72 69 70 74 69 6f 6e } //1 maptor_free_option_description
		$a_01_6 = {6d 61 70 74 6f 72 5f 66 72 65 65 5f 73 61 78 32 } //1 maptor_free_sax2
		$a_01_7 = {6d 61 70 74 6f 72 5f 6e 61 6d 65 73 70 61 63 65 73 5f 6e 61 6d 65 73 70 61 63 65 5f 69 6e 5f 73 63 6f 70 65 } //1 maptor_namespaces_namespace_in_scope
		$a_01_8 = {70 72 69 6e 74 } //10 print
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*10) >=18
 
}