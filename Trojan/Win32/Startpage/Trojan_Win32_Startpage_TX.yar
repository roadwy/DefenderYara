
rule Trojan_Win32_Startpage_TX{
	meta:
		description = "Trojan:Win32/Startpage.TX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 04 8d 44 24 14 8a 96 90 01 01 e1 40 00 80 f2 90 01 01 88 14 30 46 83 fe 0d 90 00 } //01 00 
		$a_03_1 = {73 04 8d 4c 24 4c 6a 01 53 53 51 68 90 01 01 ba 40 00 53 ff d0 39 6c 24 28 72 0d 8b 44 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}