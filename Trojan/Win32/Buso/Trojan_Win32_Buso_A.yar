
rule Trojan_Win32_Buso_A{
	meta:
		description = "Trojan:Win32/Buso.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {eb 0e c6 04 37 00 eb 08 8b 45 08 4e 03 c6 30 18 85 f6 75 f4 39 7d 08 75 10 8d 45 fc 50 ff 75 0c } //01 00 
		$a_02_1 = {74 72 56 88 18 ff 15 90 01 04 38 1e 8b f8 8b c6 74 08 80 30 90 01 01 40 38 18 75 f8 8d 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}