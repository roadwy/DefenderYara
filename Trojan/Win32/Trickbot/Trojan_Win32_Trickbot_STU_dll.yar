
rule Trojan_Win32_Trickbot_STU_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STU!dll,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e 90 02 04 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 3d 22 69 64 22 2f 3e 90 02 04 3c 61 75 74 6f 63 6f 6e 66 3e 90 02 04 3c 63 6f 6e 66 20 63 74 6c 3d 22 73 72 76 22 20 66 69 6c 65 3d 22 73 72 76 22 20 70 65 72 69 6f 64 3d 22 36 30 22 2f 3e 90 02 04 3c 2f 61 75 74 6f 63 6f 6e 66 3e 90 02 04 3c 2f 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}