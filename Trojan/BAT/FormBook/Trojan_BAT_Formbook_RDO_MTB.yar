
rule Trojan_BAT_Formbook_RDO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 53 65 72 76 69 63 65 5f 42 72 6f 6b 65 72 } //1 AppService_Broker
		$a_01_1 = {66 72 6d 58 6f 61 44 61 6e 68 4d 75 63 } //1 frmXoaDanhMuc
		$a_01_2 = {66 72 6d 54 72 69 63 68 44 61 6e 4e 68 69 65 75 } //1 frmTrichDanNhieu
		$a_01_3 = {42 61 69 42 61 6f } //1 BaiBao
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}