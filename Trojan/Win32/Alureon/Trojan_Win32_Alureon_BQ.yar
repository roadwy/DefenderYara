
rule Trojan_Win32_Alureon_BQ{
	meta:
		description = "Trojan:Win32/Alureon.BQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 43 28 6a 40 6a 25 03 c7 50 ff 15 90 01 04 8b 43 28 6a 09 03 f0 03 f8 59 f3 a5 8d 45 0c 50 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}