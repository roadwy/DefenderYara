
rule Trojan_Win32_StartPage_ZM_bit{
	meta:
		description = "Trojan:Win32/StartPage.ZM!bit,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 6f 00 6d 00 65 00 6c 00 6f 00 63 00 6b 00 78 00 78 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_1 = {6b 00 75 00 73 00 72 00 74 00 72 00 73 00 74 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 68 6f 6d 65 6c 6f 63 6b } //01 00 
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 68 70 63 6e 74 31 31 30 } //00 00 
	condition:
		any of ($a_*)
 
}