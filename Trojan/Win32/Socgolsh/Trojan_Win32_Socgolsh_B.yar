
rule Trojan_Win32_Socgolsh_B{
	meta:
		description = "Trojan:Win32/Socgolsh.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 81 3c 07 56 69 75 90 01 01 66 81 7c 07 02 72 74 75 90 01 01 81 7c 07 09 6c 6f 63 00 75 90 00 } //01 00 
		$a_03_1 = {66 81 7c 07 01 69 72 75 90 01 01 66 81 7c 07 03 74 75 75 90 01 01 81 7c 07 09 6c 6f 63 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}