
rule Trojan_Win32_Badkey_A{
	meta:
		description = "Trojan:Win32/Badkey.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 db 43 68 90 01 02 00 00 e8 15 00 00 00 6a 00 6a 00 6a 00 53 e8 03 00 00 00 eb e7 90 00 } //01 00 
		$a_00_1 = {6b 65 79 62 64 5f 65 76 65 6e 74 00 75 73 65 72 33 32 2e 64 6c 6c 00 } //01 00 
		$a_00_2 = {53 6c 65 65 70 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}