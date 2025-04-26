
rule Trojan_BAT_Pony_KAY_MTB{
	meta:
		description = "Trojan:BAT/Pony.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 2b 40 67 4c 7d f9 6f 6a 4a 5f 4d 46 67 46 37 55 68 6a 3a 5f 42 46 67 46 c5 52 68 } //3
		$a_01_1 = {b3 3b 53 68 6a 4e 68 5b dc 74 4a 54 40 48 fd d4 0f 36 1c 47 01 4e cd b0 0b 72 29 b4 } //4
		$a_01_2 = {7f 4d 74 e0 0f d3 9e 6f 6d 61 6c b3 14 6e ad 6f 51 72 80 9a b3 ba 2a 6e 6a 4a 73 38 79 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}