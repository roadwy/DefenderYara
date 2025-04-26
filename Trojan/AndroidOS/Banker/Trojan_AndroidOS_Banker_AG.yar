
rule Trojan_AndroidOS_Banker_AG{
	meta:
		description = "Trojan:AndroidOS/Banker.AG,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {54 53 4b 5f 46 49 4e 49 53 48 5f 41 43 54 5f 4f 4b } //1 TSK_FINISH_ACT_OK
		$a_00_1 = {50 50 5f 4f 55 5f 43 54 5f 43 4f 4e 46 49 52 4d 41 52 2e 2e 2e } //1 PP_OU_CT_CONFIRMAR...
		$a_00_2 = {52 45 53 45 54 5f 41 43 54 5f 52 45 43 } //1 RESET_ACT_REC
		$a_00_3 = {43 54 5f 44 41 54 41 5f 4f 4b } //1 CT_DATA_OK
		$a_00_4 = {4b 45 59 5f 43 5f 49 4e 53 45 52 54 45 44 } //1 KEY_C_INSERTED
		$a_00_5 = {52 45 56 49 53 41 44 4f 5f 41 43 54 5f 4f 4b } //1 REVISADO_ACT_OK
		$a_00_6 = {46 5f 43 4f 4e 46 49 52 4d 41 44 4f } //1 F_CONFIRMADO
		$a_00_7 = {62 74 6e 5f 74 72 5f 61 63 74 69 6f 6e } //1 btn_tr_action
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}