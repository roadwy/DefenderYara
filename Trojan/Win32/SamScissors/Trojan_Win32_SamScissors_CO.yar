
rule Trojan_Win32_SamScissors_CO{
	meta:
		description = "Trojan:Win32/SamScissors.CO,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {ff d0 ba 82 84 1e 00 b9 40 00 00 00 ff 15 90 01 04 49 89 06 48 85 c0 0f 84 59 02 00 00 90 00 } //01 00 
		$a_00_1 = {70 00 6c 00 61 00 63 00 65 00 73 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 } //01 00  places.sqlite
		$a_00_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 75 00 72 00 6c 00 2c 00 20 00 74 00 69 00 74 00 6c 00 65 00 20 00 46 00 52 00 } //01 00  SELECT url, title FR
		$a_00_3 = {25 00 73 00 20 00 20 00 20 00 3a 00 20 00 20 00 20 00 25 00 73 00 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}