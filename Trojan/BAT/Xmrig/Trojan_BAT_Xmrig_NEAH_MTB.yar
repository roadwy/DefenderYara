
rule Trojan_BAT_Xmrig_NEAH_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 28 11 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de db 07 2a } //10
		$a_01_1 = {43 68 69 6e 68 44 6f 2e 54 72 61 6e 73 61 63 74 69 6f 6e 73 } //5 ChinhDo.Transactions
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}