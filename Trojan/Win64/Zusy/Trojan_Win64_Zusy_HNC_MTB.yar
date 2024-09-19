
rule Trojan_Win64_Zusy_HNC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {9a 73 67 65 67 66 62 65 68 62 66 6a 89 66 66 6f 68 66 6f 69 6a 63 6b 66 6b 6b 65 6d 6d 8f 71 64 } //5
		$a_01_1 = {24 40 48 8d 15 ab 58 00 00 4c 89 e1 e8 69 00 00 30 34 20 2d 20 44 6f 77 6e 6c 6f 61 64 73 2e 6c 6e 6b 00 6c 6e 6b 00 00 1c 0f 01 01 03 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}