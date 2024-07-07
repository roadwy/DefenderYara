
rule Trojan_Win64_Ropest_B{
	meta:
		description = "Trojan:Win64/Ropest.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d e4 85 43 31 0f 84 90 01 04 3d f7 dc ee b1 0f 84 90 00 } //1
		$a_01_1 = {74 17 48 63 40 3c b3 01 42 8b 4c 18 58 89 4d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}