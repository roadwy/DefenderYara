
rule Trojan_AndroidOS_Piom_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 4d 41 53 4b 5f 43 54 5f 4d 4f 44 53 } //1 _MASK_CT_MODS
		$a_01_1 = {54 41 53 4b 5f 53 45 4e 44 5f 53 4d 53 } //1 TASK_SEND_SMS
		$a_00_2 = {73 65 6e 64 69 6e 67 20 73 6d 73 3a 20 75 72 6c } //1 sending sms: url
		$a_00_3 = {61 6f 2e 71 70 6c 61 7a 65 2e 63 6f 6d 2f 61 64 6d 2f 6d 61 6e 2f 73 6c 69 73 74 2e 61 73 70 } //1 ao.qplaze.com/adm/man/slist.asp
		$a_01_4 = {4d 4f 44 5f 53 43 52 49 50 54 5f 52 55 4e } //1 MOD_SCRIPT_RUN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}