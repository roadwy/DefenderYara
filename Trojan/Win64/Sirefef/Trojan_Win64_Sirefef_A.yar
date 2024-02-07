
rule Trojan_Win64_Sirefef_A{
	meta:
		description = "Trojan:Win64/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 46 30 63 6e 63 74 48 89 7e 28 } //01 00 
		$a_01_1 = {48 b9 47 42 ca 72 2e 8e 40 42 45 32 d2 48 33 c1 48 b9 } //01 00 
		$a_01_2 = {48 b8 48 83 ec 20 ff d0 48 83 4c } //01 00 
		$a_01_3 = {73 74 61 74 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 73 26 61 3d 25 75 } //01 00  stat.php?w=%u&i=%s&a=%u
		$a_01_4 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 64 72 6f 70 65 72 } //00 00  x64\release\droper
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Sirefef_A_2{
	meta:
		description = "Trojan:Win64/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 46 30 63 6e 63 74 48 89 7e 28 } //01 00 
		$a_01_1 = {48 b9 47 42 ca 72 2e 8e 40 42 45 32 d2 48 33 c1 48 b9 } //01 00 
		$a_01_2 = {48 b8 48 83 ec 20 ff d0 48 83 4c } //01 00 
		$a_01_3 = {73 74 61 74 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 73 26 61 3d 25 75 } //01 00  stat.php?w=%u&i=%s&a=%u
		$a_01_4 = {78 36 34 5c 72 65 6c 65 61 73 65 5c 64 72 6f 70 65 72 } //00 00  x64\release\droper
	condition:
		any of ($a_*)
 
}