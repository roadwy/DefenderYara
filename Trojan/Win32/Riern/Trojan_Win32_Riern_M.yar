
rule Trojan_Win32_Riern_M{
	meta:
		description = "Trojan:Win32/Riern.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c eb 90 01 01 ff 75 0c 57 ff 75 08 e8 90 01 04 83 c4 0c 39 7d 10 74 90 01 01 39 75 0c 73 0e 90 00 } //01 00 
		$a_01_1 = {56 53 53 6a 1a 53 ff d0 3b c3 } //00 00 
	condition:
		any of ($a_*)
 
}