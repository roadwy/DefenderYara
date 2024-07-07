
rule _PseudoThreat_40000023{
	meta:
		description = "!PseudoThreat_40000023,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 64 72 49 6e 73 75 72 61 6e 63 65 45 76 65 6e 74 45 78 00 } //1 摬䥲獮牵湡散癅湥䕴x
		$a_01_1 = {4c 6f 61 64 65 72 53 74 61 72 74 65 64 5f 25 58 00 } //1
		$a_00_2 = {2f 70 68 70 2f 6c 6f 61 64 65 72 33 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //1 /php/loader3/download.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}