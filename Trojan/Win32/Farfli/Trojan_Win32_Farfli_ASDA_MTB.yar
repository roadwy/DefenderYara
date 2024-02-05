
rule Trojan_Win32_Farfli_ASDA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 f2 c7 45 ec 47 65 74 50 c7 45 f0 72 6f 63 41 c7 45 f4 64 64 72 65 66 c7 45 f8 73 73 } //01 00 
		$a_01_1 = {73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 } //01 00 
		$a_01_2 = {76 00 69 00 72 00 74 00 75 00 61 00 6c 00 62 00 6f 00 78 00 } //01 00 
		$a_01_3 = {73 00 61 00 6d 00 70 00 6c 00 65 00 76 00 6d 00 } //01 00 
		$a_01_4 = {63 00 75 00 63 00 6b 00 6f 00 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}