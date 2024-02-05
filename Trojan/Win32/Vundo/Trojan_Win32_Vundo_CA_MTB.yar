
rule Trojan_Win32_Vundo_CA_MTB{
	meta:
		description = "Trojan:Win32/Vundo.CA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba e2 7f 9c d5 30 10 40 49 0f 85 } //01 00 
		$a_01_1 = {8b df 2b d8 8a 03 88 07 47 bb 02 00 00 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}