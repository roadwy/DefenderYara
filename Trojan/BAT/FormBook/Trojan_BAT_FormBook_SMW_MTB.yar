
rule Trojan_BAT_FormBook_SMW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_1 = {54 69 63 54 61 63 54 6f 65 } //1 TicTacToe
		$a_81_2 = {41 70 70 53 69 73 74 65 6d 61 47 61 72 61 67 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 AppSistemaGaragem.Properties.Resources
		$a_00_3 = {00 02 0f 01 28 64 00 00 0a 6f 62 00 00 0a 00 02 0f 01 28 63 00 00 0a 6f 62 00 00 0a 19 0b 2b c6 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}