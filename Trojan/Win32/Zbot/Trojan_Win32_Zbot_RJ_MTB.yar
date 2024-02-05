
rule Trojan_Win32_Zbot_RJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 cf 87 da 01 75 c0 03 4d a0 4a 89 75 b8 2b ce 99 33 d6 03 ce 03 d2 87 ca 2b d9 03 4d c0 89 6d f0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 4d 62 58 62 32 5a 4e 64 68 63 39 6d 6e 6f 73 41 57 49 6a 57 34 57 43 4a 56 30 41 73 4f 71 6d 69 56 52 42 52 6a 63 4a 75 43 32 61 46 76 77 30 52 75 55 6e 4b 6d 73 6a 31 6c 66 7a } //01 00 
		$a_01_1 = {42 50 49 38 75 76 69 78 35 61 64 79 32 65 72 72 58 78 32 65 33 55 73 4a 4d 6e 79 67 37 36 69 4f 50 34 71 6e 4c 4b 6b 64 6a 66 68 4a 78 6e 69 46 65 37 63 6e 31 55 30 43 66 59 74 6c 63 31 6b 76 45 6f } //01 00 
		$a_01_2 = {48 36 37 71 57 70 77 49 58 55 48 74 79 42 4a 63 36 6c 38 71 50 6e 74 32 68 30 32 73 51 79 6a 73 63 6d 7a 6b 67 4f 55 32 5a 38 34 44 52 4c 41 57 55 61 33 72 39 6b 36 51 34 57 61 30 44 47 } //01 00 
		$a_01_3 = {48 73 30 68 44 44 35 4e 57 68 46 6f 72 55 54 71 6a 6f 37 4d 39 34 64 39 76 5a 6b 57 76 6d 76 30 50 45 70 69 4b 79 45 47 4c 31 68 38 51 67 37 70 6f 6d 59 32 4b 65 46 61 } //00 00 
	condition:
		any of ($a_*)
 
}