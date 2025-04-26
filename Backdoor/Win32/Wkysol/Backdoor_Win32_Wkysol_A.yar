
rule Backdoor_Win32_Wkysol_A{
	meta:
		description = "Backdoor:Win32/Wkysol.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {7d 21 8b 4d fc 33 d2 8a 54 0d 08 8b 45 fc 33 c9 8a 4c 05 4c 33 d1 8b 85 90 90 00 00 00 03 45 fc 88 10 eb ce } //2
		$a_01_1 = {8a 54 04 0c 8a 5c 04 50 32 d3 88 14 30 40 3b c1 7c ee } //2
		$a_01_2 = {54 43 50 09 50 49 44 3a 25 35 64 3b 09 50 4f 52 54 3a 25 35 64 09 50 41 54 48 3a 25 73 } //5
		$a_01_3 = {31 39 39 39 30 38 31 37 00 } //5
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=12
 
}