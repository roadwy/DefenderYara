
rule Trojan_Win64_Floomyeda_D{
	meta:
		description = "Trojan:Win64/Floomyeda.D,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 00 53 65 72 76 69 63 65 4d 61 69 6e } //0a 00 
		$a_01_1 = {77 63 6e 62 69 73 5f 78 36 34 2e 64 6c 6c } //0a 00 
		$a_01_2 = {77 63 6e 62 69 73 5f 78 38 36 2e 64 6c 6c } //0a 00 
		$a_01_3 = {77 63 6e 62 69 73 5f 78 33 32 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}