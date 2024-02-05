
rule Ransom_Win32_Satan_S_MSR{
	meta:
		description = "Ransom:Win32/Satan.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 35 73 73 35 63 } //01 00 
		$a_01_1 = {35 73 73 35 63 } //01 00 
		$a_01_2 = {35 73 73 35 63 5f 74 6f 6b 65 6e } //01 00 
		$a_01_3 = {35 73 73 35 63 5f 43 52 59 50 54 } //01 00 
		$a_01_4 = {35 73 73 35 63 40 6d 61 69 6c 2e 72 75 } //00 00 
	condition:
		any of ($a_*)
 
}