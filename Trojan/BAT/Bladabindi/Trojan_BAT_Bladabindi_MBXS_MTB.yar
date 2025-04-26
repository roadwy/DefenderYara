
rule Trojan_BAT_Bladabindi_MBXS_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {36 42 30 77 36 61 00 63 48 38 49 58 63 77 51 59 34 50 65 68 32 71 70 41 6e 00 52 32 6d 49 61 } //3
		$a_01_1 = {74 69 6f 6e 00 76 69 64 65 6f 73 6f 66 74 } //2 楴湯瘀摩潥潳瑦
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}