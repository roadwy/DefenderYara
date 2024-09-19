
rule Trojan_AndroidOS_Mamont_F{
	meta:
		description = "Trojan:AndroidOS/Mamont.F,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 4f 52 4f 4e 41 5f 50 41 59 5f 54 52 41 4e 53 46 45 52 5f 43 4f 4d 50 4c 45 54 49 4f 4e } //2 KORONA_PAY_TRANSFER_COMPLETION
		$a_01_1 = {68 61 6e 64 6c 65 53 69 6d 54 72 61 6e 73 66 65 72 43 6f 6e 66 69 72 6d 61 74 69 6f 6e 43 6f 64 65 52 65 63 65 69 70 74 } //2 handleSimTransferConfirmationCodeReceipt
		$a_01_2 = {67 65 74 4e 65 65 64 44 65 66 61 75 6c 74 53 6d 73 41 70 70 50 65 72 6d 69 73 73 69 6f 6e } //2 getNeedDefaultSmsAppPermission
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}