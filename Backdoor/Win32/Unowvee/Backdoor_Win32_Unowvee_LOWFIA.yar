
rule Backdoor_Win32_Unowvee_LOWFIA{
	meta:
		description = "Backdoor:Win32/Unowvee.LOWFIA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 2e 58 66 90 02 0a 6a 70 58 66 90 02 0a 6a 6e 58 66 90 02 0a 6a 67 90 00 } //01 00 
		$a_03_1 = {8a 14 07 8b cf 83 e1 01 80 c2 05 32 54 90 01 02 88 14 07 47 3b fe 7c 90 00 } //01 00 
		$a_03_2 = {6e 6e 6a 6a c7 90 02 0a 6a 68 62 6e c7 90 02 0a 4b 76 30 30 c7 90 02 0a 6d 35 47 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}