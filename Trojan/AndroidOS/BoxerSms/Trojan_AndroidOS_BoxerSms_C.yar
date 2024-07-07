
rule Trojan_AndroidOS_BoxerSms_C{
	meta:
		description = "Trojan:AndroidOS/BoxerSms.C,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 72 61 6e 74 41 63 63 65 73 73 2e 6a 61 76 61 } //1 GrantAccess.java
		$a_01_1 = {42 45 45 45 4c 49 4e 45 5f 49 44 } //1 BEEELINE_ID
		$a_01_2 = {4c 49 4e 4b 5f 54 48 41 54 5f 57 41 53 5f 44 4f 4e 45 } //1 LINK_THAT_WAS_DONE
		$a_01_3 = {4f 46 46 45 52 54 5f 41 43 54 49 56 49 54 59 } //1 OFFERT_ACTIVITY
		$a_01_4 = {66 75 6c 6c 5f 6f 66 66 65 72 74 73 5f 74 65 78 74 } //1 full_offerts_text
		$a_01_5 = {69 5f 64 69 73 61 67 72 65 65 5f 6f 66 66 65 72 74 } //1 i_disagree_offert
		$a_01_6 = {69 5f 61 63 63 65 70 74 5f 6f 66 66 65 72 74 } //1 i_accept_offert
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}