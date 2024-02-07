
rule Trojan_Win32_Sakurel_B_dha{
	meta:
		description = "Trojan:Win32/Sakurel.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00 } //01 00  搥潟彦搥晟牯╟彳湯╟s
		$a_00_1 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22 00 } //01 00 
		$a_00_2 = {3f 70 68 6f 74 6f 69 64 3d 00 } //02 00  瀿潨潴摩=
		$a_03_3 = {68 f4 01 00 00 ff 15 90 01 04 81 c3 00 90 90 01 00 3b 9d 90 01 02 ff ff 0f 86 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sakurel_B_dha_2{
	meta:
		description = "Trojan:Win32/Sakurel.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00 } //01 00  搥潟彦搥晟牯╟彳湯╟s
		$a_01_1 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 2f 71 20 22 25 73 22 00 } //01 00 
		$a_03_2 = {3f 72 65 73 69 64 3d 25 64 90 02 0f 26 70 68 6f 74 6f 69 64 3d 00 90 00 } //01 00 
		$a_03_3 = {68 f4 01 00 00 ff 15 90 01 04 81 c5 00 90 90 01 00 3b eb 0f 86 90 00 } //00 00 
		$a_00_4 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}