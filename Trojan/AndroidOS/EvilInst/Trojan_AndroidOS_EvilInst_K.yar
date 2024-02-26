
rule Trojan_AndroidOS_EvilInst_K{
	meta:
		description = "Trojan:AndroidOS/EvilInst.K,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 69 72 74 69 6e 52 65 63 65 69 76 65 72 } //02 00  ConfirtinReceiver
		$a_01_1 = {53 45 4e 44 4b 57 52 4f } //02 00  SENDKWRO
		$a_01_2 = {46 4c 41 47 5f 43 4f 4e 46 49 52 4d 5f 4b 57 31 } //02 00  FLAG_CONFIRM_KW1
		$a_01_3 = {4e 68 61 6e 52 65 63 65 69 76 65 72 } //00 00  NhanReceiver
	condition:
		any of ($a_*)
 
}