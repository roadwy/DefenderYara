
rule Trojan_Win32_Farfli_BV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 0c 38 80 f1 19 80 c1 7a 88 0c 38 40 3b c6 7c } //01 00 
		$a_01_1 = {5b 45 78 65 63 75 74 65 5d } //01 00 
		$a_01_2 = {4c 65 74 20 6d 65 20 65 78 69 74 } //01 00 
		$a_01_3 = {43 6f 6e 6e 65 63 74 20 4f 4b 21 } //00 00 
	condition:
		any of ($a_*)
 
}