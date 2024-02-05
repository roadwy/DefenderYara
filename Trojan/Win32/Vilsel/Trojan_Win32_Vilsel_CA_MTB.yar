
rule Trojan_Win32_Vilsel_CA_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 fe 10 27 00 00 6a 00 76 1f 8d 4c 24 10 8d 94 24 18 01 00 00 51 68 10 27 00 00 52 57 ff d3 81 ee 10 27 00 00 75 d9 } //00 00 
	condition:
		any of ($a_*)
 
}