
rule Trojan_Win32_Wingbird_C_dha{
	meta:
		description = "Trojan:Win32/Wingbird.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 c0 58 0f 84 90 01 04 cc cc cc cc cc 8b ff 55 8b ec 90 00 } //01 00 
		$a_03_1 = {31 c9 59 0f 84 90 01 04 cc cc cc cc cc 8b ff 55 8b ec 90 00 } //01 00 
		$a_03_2 = {31 d2 5a 0f 84 90 01 04 cc cc cc cc cc 8b ff 55 8b ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}