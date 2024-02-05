
rule Backdoor_Win32_Poison_BT{
	meta:
		description = "Backdoor:Win32/Poison.BT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac c0 c0 03 34 41 c0 c0 03 34 52 c0 c0 03 34 43 c0 c0 03 34 48 c0 c0 03 34 59 90 04 01 01 aa 90 00 } //01 00 
		$a_03_1 = {85 c0 74 12 8b 08 6a 01 49 5e d3 e6 0b d6 89 57 fc 8b 40 04 eb 90 04 01 01 ea 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}