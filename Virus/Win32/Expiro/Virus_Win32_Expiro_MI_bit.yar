
rule Virus_Win32_Expiro_MI_bit{
	meta:
		description = "Virus:Win32/Expiro.MI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5f 30 8b 03 81 e0 df 00 df 00 8b 5b 0c c1 e3 08 03 d8 c1 eb 02 81 } //01 00 
		$a_03_1 = {48 8b 06 85 c3 35 90 01 04 39 c7 89 07 29 d8 83 c6 04 4b 83 c7 04 4b 4b 4b 83 fb 00 74 05 90 00 } //01 00 
		$a_01_2 = {b8 0a 00 00 00 99 f7 fb 89 45 f0 8b 45 20 03 45 18 01 f0 } //00 00 
	condition:
		any of ($a_*)
 
}