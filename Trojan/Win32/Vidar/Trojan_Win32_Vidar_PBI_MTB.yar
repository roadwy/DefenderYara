
rule Trojan_Win32_Vidar_PBI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 00 33 d2 51 b9 08 00 00 00 d1 c0 8a fc 8a e6 d1 cb 49 75 90 01 01 8b c3 59 90 00 } //01 00 
		$a_03_1 = {8b cf 83 e1 03 75 90 01 01 46 0f b6 5e 04 ba 11 00 00 00 d3 c2 23 d3 ac 0a c2 aa ff 4d 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}