
rule Trojan_BAT_LokiBot_CCAV_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CCAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 18 5b 02 07 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 07 18 58 0b 07 02 6f 90 01 01 00 00 0a fe 04 0c 08 2d db 90 00 } //1
		$a_01_1 = {51 75 61 6e 4c 79 53 6f 54 69 65 74 4b 69 65 6d } //1 QuanLySoTietKiem
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}