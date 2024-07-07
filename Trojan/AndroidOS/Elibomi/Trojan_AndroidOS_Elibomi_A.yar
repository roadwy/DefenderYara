
rule Trojan_AndroidOS_Elibomi_A{
	meta:
		description = "Trojan:AndroidOS/Elibomi.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {78 76 61 62 7a 65 7a 69 74 66 74 } //1 xvabzezitft
		$a_00_1 = {61 62 78 76 6e 69 74 69 64 } //1 abxvnitid
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}