
rule Trojan_Win64_Sirefef_AL{
	meta:
		description = "Trojan:Win64/Sirefef.AL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 09 00 00 00 48 8b cb c7 45 90 01 01 a8 01 00 00 48 c7 45 90 01 01 00 00 00 60 c7 45 90 01 01 01 00 00 00 c7 45 90 01 01 40 00 00 00 ff 15 90 01 04 85 c0 74 90 01 01 ff 15 90 01 04 85 c0 74 01 cc 90 00 } //01 00 
		$a_01_1 = {38 30 30 30 30 30 63 62 2e 40 } //00 00 
	condition:
		any of ($a_*)
 
}