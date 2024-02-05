
rule Trojan_Win32_Startpage_RR{
	meta:
		description = "Trojan:Win32/Startpage.RR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 61 70 70 69 6e 67 5f 68 6b 5f 63 6e 74 72 5f } //03 00 
		$a_01_1 = {7e 6a 61 6b 65 31 39 38 30 } //02 00 
		$a_01_2 = {6a 00 73 00 63 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}