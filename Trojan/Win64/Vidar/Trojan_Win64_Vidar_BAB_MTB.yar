
rule Trojan_Win64_Vidar_BAB_MTB{
	meta:
		description = "Trojan:Win64/Vidar.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 5f 63 74 6c 5f 70 61 72 73 65 72 } //1 main._ctl_parser
		$a_81_1 = {6d 61 69 6e 2e 5f 6e 6c 5f 65 78 70 61 6e 64 5f 61 6c 69 61 73 } //1 main._nl_expand_alias
		$a_81_2 = {6d 61 69 6e 2e 5f 6e 6c 5f 6d 73 67 5f 63 61 74 5f 63 6e 74 72 } //1 main._nl_msg_cat_cntr
		$a_81_3 = {6d 61 69 6e 2e 6c 69 62 69 6e 74 6c 5f 73 65 74 5f 72 65 6c 6f 63 61 74 69 6f 6e 5f 70 72 65 66 69 78 } //1 main.libintl_set_relocation_prefix
		$a_81_4 = {6d 61 69 6e 2e 62 69 6e 64 5f 74 65 78 74 64 6f 6d 61 69 6e 5f 63 6f 64 65 73 65 74 } //1 main.bind_textdomain_codeset
		$a_81_5 = {6d 61 69 6e 2e 6c 69 62 69 6e 74 6c 5f 62 69 6e 64 5f 74 65 78 74 64 6f 6d 61 69 6e 5f 63 6f 64 65 73 65 74 } //1 main.libintl_bind_textdomain_codeset
		$a_81_6 = {6d 61 69 6e 2e 6e 67 65 74 74 65 78 74 } //1 main.ngettext
		$a_81_7 = {6d 61 69 6e 2e 74 65 78 74 64 6f 6d 61 69 6e } //1 main.textdomain
		$a_81_8 = {6d 61 69 6e 2e 62 69 6e 64 74 65 78 74 64 6f 6d 61 69 6e } //1 main.bindtextdomain
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}