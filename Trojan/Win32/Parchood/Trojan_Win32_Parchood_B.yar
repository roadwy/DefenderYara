
rule Trojan_Win32_Parchood_B{
	meta:
		description = "Trojan:Win32/Parchood.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 f8 d3 c3 90 09 09 00 5f eb 03 80 e9 20 80 f9 20 90 00 } //01 00 
		$a_03_1 = {f4 eb 06 04 90 09 34 00 ff ff 53 50 68 02 00 00 80 ff 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}