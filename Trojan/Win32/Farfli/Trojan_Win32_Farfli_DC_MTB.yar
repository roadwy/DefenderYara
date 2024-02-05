
rule Trojan_Win32_Farfli_DC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {8a 0c 18 80 e9 17 80 f1 3e 80 c1 17 88 0c 18 40 3b 45 0c 7c } //01 00 
		$a_01_1 = {77 77 77 2e 74 65 73 74 7a 61 6b 65 2e 63 6f 6d } //01 00 
		$a_01_2 = {43 3a 5c 54 45 4d 50 5c 73 79 73 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}