
rule Backdoor_Win32_Miki{
	meta:
		description = "Backdoor:Win32/Miki,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 67 41 6f 41 43 41 41 4a 41 42 7a 41 47 67 41 52 51 42 4d 41 45 77 41 53 51 42 45 41 46 73 41 4d 51 42 64 41 43 73 41 4a 41 42 7a 41 45 67 41 52 51 42 73 41 45 77 41 53 51 42 6b 41 46 73 41 4d 51 41 7a 41 46 30 41 4b } //00 00 
	condition:
		any of ($a_*)
 
}