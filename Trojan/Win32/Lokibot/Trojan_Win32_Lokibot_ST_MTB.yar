
rule Trojan_Win32_Lokibot_ST_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 79 00 6e 00 65 00 68 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_1 = {51 75 70 5a 69 6c 6c 61 5c 70 72 6f 66 69 6c 65 73 5c 64 65 66 61 75 6c 74 5c 62 72 6f 77 73 65 64 61 74 61 2e 64 62 } //01 00 
		$a_01_2 = {2f 67 72 6f 75 70 2f 6f 6e 65 2f 74 77 6f 2f 74 68 72 65 65 2f 66 6f 75 72 2f 66 69 76 65 2f 66 72 65 2e 70 68 70 } //01 00 
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 45 78 70 6c 6f 72 65 72 6f 72 65 72 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_ST_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.ST!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 c7 00 8b 4d fc 03 cf 83 c7 00 8a 10 83 c7 00 83 c7 00 32 55 fa 88 11 83 c7 00 83 c7 00 83 c7 00 83 c7 00 8a 55 fb 30 11 83 c7 00 47 40 4e 75 cf } //00 00 
	condition:
		any of ($a_*)
 
}