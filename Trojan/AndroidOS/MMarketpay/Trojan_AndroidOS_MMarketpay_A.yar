
rule Trojan_AndroidOS_MMarketpay_A{
	meta:
		description = "Trojan:AndroidOS/MMarketpay.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 73 75 72 6d 20 75 72 6c } //2 consurm url
		$a_01_1 = {76 61 6c 69 64 61 74 69 6f 6e 20 73 75 62 6d 69 74 55 72 6c 3a } //2 validation submitUrl:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}