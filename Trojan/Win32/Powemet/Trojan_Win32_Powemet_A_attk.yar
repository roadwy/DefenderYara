
rule Trojan_Win32_Powemet_A_attk{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 90 02 f0 2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_02_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 90 02 f0 2d 00 69 00 3a 00 68 00 74 00 74 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powemet_A_attk_2{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //01 00 
		$a_00_1 = {2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //01 00 
		$a_00_2 = {2d 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //0a 00 
		$a_00_3 = {20 00 73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powemet_A_attk_3{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //05 00 
		$a_00_1 = {2f 00 73 00 } //05 00 
		$a_00_2 = {2f 00 75 00 } //01 00 
		$a_00_3 = {2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //01 00 
		$a_00_4 = {2f 00 69 00 3a 00 5c 00 5c 00 } //05 00 
		$a_00_5 = {73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}