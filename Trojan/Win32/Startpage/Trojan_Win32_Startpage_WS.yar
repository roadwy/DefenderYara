
rule Trojan_Win32_Startpage_WS{
	meta:
		description = "Trojan:Win32/Startpage.WS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 48 65 6c 70 5c 68 64 67 65 72 2e 78 6d 6c } //01 00 
		$a_01_1 = {5c 31 30 33 33 5c 73 64 61 2e 74 78 74 } //01 00 
		$a_01_2 = {2e 62 61 69 64 75 6f 2e 6f 72 67 } //01 00 
		$a_01_3 = {2f 31 32 33 35 36 33 33 2e 33 33 32 32 2e 6f 72 67 2f 47 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}