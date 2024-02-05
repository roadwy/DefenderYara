
rule Trojan_Win32_Azorult_DS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 33 c0 55 68 90 01 04 64 ff 30 64 89 20 83 2d 90 01 04 01 0f 90 00 } //01 00 
		$a_02_1 = {6a 00 6a 00 e8 90 01 04 4b 90 0a 10 00 bb 90 01 03 00 90 02 10 75 90 00 } //01 00 
		$a_02_2 = {5a 59 59 64 89 10 68 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}