
rule Trojan_Win32_Bocinex_gen_B{
	meta:
		description = "Trojan:Win32/Bocinex.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 6a 00 68 00 00 00 80 6a 00 6a 00 51 50 89 45 ec ff 15 } //01 00 
		$a_01_1 = {89 45 f8 6a 00 68 00 00 00 80 6a 00 6a 00 8b 45 08 50 8b 4d f8 51 ff 15 } //02 00 
		$a_00_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //05 00  \CurrentVersion\Policies\Explorer\run
		$a_01_3 = {2e 65 78 65 20 2d 67 20 79 65 73 20 2d 6f 20 68 74 74 70 3a 2f 2f } //00 00  .exe -g yes -o http://
	condition:
		any of ($a_*)
 
}