
rule Trojan_AndroidOS_SMforw_F{
	meta:
		description = "Trojan:AndroidOS/SMforw.F,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 76 48 65 6c 70 65 72 73 } //02 00  ConvHelpers
		$a_01_1 = {4c 63 6f 6d 2f 65 34 61 2f 72 75 6e 74 69 6d 65 2f 68 65 6c 70 65 72 73 2f 53 74 6d 74 48 65 6c 70 65 72 73 } //01 00  Lcom/e4a/runtime/helpers/StmtHelpers
		$a_00_2 = {73 6d 73 43 6f 6c 75 6d 6e } //00 00  smsColumn
	condition:
		any of ($a_*)
 
}