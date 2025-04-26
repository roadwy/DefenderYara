
rule Trojan_BAT_Injuke_NEAD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 75 00 00 0a 6f 77 00 00 0a 00 06 18 6f 78 00 00 0a 00 06 18 6f 79 00 00 0a 00 06 6f 7a 00 00 0a 0b 07 02 16 02 8e 69 6f 7b 00 00 0a 0c 2b 00 08 2a } //10
		$a_01_1 = {24 00 24 00 24 00 5f 00 49 00 5f 00 6e 00 5f 00 76 00 5f 00 6f 00 5f 00 6b 00 5f 00 65 00 5f 00 24 00 24 00 24 00 } //2 $$$_I_n_v_o_k_e_$$$
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}