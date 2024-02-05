
rule Trojan_Win32_Farfli_PF{
	meta:
		description = "Trojan:Win32/Farfli.PF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b e5 5d 8a 10 8a 19 32 da 88 19 90 55 8b ec 83 c4 0c 83 ec 0c 8b e5 90 5d 8a 10 8a 19 02 da 88 19 } //01 00 
		$a_01_1 = {53 5b 90 8b e5 90 5d 33 c9 c6 45 fc 52 66 89 4d fd c6 45 fd 75 88 4d ff c6 45 fe 6e 90 55 8b ec 41 49 83 c4 09 83 ec 09 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}