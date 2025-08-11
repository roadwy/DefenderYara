
rule Trojan_BAT_Cerbu_ARA_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 04 00 00 6a 5a 20 00 04 00 00 6a 5a 20 00 04 00 00 6a 5a 0b 06 6f ?? ?? ?? 0a 2c 0b 06 6f ?? ?? ?? 0a 07 fe 02 2b 01 16 0c de 05 } //2
		$a_01_1 = {5c 75 69 68 64 66 68 6a 64 73 61 68 66 64 73 66 2e 70 64 62 } //2 \uihdfhjdsahfdsf.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}