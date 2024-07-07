
rule Trojan_Win64_JaggedToe_C_dha{
	meta:
		description = "Trojan:Win64/JaggedToe.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 90 01 01 25 73 0a 00 44 69 73 6b 48 61 6e 64 6c 65 3a 20 25 64 2c 20 57 69 70 65 64 3a 20 25 64 2c 20 45 72 72 6f 72 3a 20 25 64 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}