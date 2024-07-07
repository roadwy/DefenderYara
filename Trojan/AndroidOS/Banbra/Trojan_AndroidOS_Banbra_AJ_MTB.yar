
rule Trojan_AndroidOS_Banbra_AJ_MTB{
	meta:
		description = "Trojan:AndroidOS/Banbra.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 66 69 72 6d 61 2f 64 6f 73 69 63 6b 6f 2f 63 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 2f 53 65 72 76 65 72 } //1 Lcom/firma/dosicko/communication/Server
		$a_00_1 = {53 65 72 76 65 72 24 61 75 74 6f 50 69 6e 67 } //1 Server$autoPing
		$a_00_2 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 50 61 63 6b 61 67 65 73 } //1 getInstalledPackages
		$a_00_3 = {67 65 74 52 6f 6f 74 49 6e 41 63 74 69 76 65 57 69 6e 64 6f 77 } //1 getRootInActiveWindow
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}