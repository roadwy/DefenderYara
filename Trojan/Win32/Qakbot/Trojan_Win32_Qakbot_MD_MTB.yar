
rule Trojan_Win32_Qakbot_MD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 e8 90 01 04 8b d8 8b 45 d8 83 c0 04 03 45 a4 03 d8 e8 90 01 04 2b d8 89 5d d8 8b 45 a8 3b 45 cc 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 65 74 56 65 72 73 69 6f 6e 49 6e 66 6f } //01 00 
		$a_01_1 = {6c 61 73 71 61 6c 5f 61 6c 6c 6f 63 5f 6d 65 6d 6f 72 79 } //01 00 
		$a_01_2 = {6c 61 73 71 61 6c 5f 65 76 61 6c 75 61 74 69 6f 6e 5f 63 6f 6e 74 65 78 74 5f 73 65 74 5f 62 61 73 65 5f 75 72 69 } //01 00 
		$a_01_3 = {6c 61 73 71 61 6c 5f 65 78 70 72 65 73 73 69 6f 6e 5f 63 6f 6d 70 61 72 65 } //01 00 
		$a_01_4 = {6c 61 73 71 61 6c 5f 66 72 65 65 5f 65 76 61 6c 75 61 74 69 6f 6e 5f 63 6f 6e 74 65 78 74 } //01 00 
		$a_01_5 = {6c 61 73 71 61 6c 5f 67 72 61 70 68 5f 70 61 74 74 65 72 6e 5f 61 64 64 5f 73 75 62 5f 67 72 61 70 68 5f 70 61 74 74 65 72 6e } //0a 00 
		$a_01_6 = {70 72 69 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}