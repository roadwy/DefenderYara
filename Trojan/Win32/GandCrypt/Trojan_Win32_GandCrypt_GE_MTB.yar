
rule Trojan_Win32_GandCrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 a1 90 01 04 69 c0 fd 43 03 00 56 a3 90 01 04 81 05 90 01 04 c3 9e 26 00 81 3d 90 01 04 a5 02 00 00 8b 35 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {50 6a 00 ff d7 81 fe 4a 38 02 00 7e 90 01 01 b9 db 86 00 00 66 3b d9 75 90 01 01 46 81 fe 36 9c 97 01 7c 90 00 } //01 00 
		$a_02_2 = {33 f6 85 ff 7e 90 01 01 53 81 ff 69 04 00 00 75 90 01 01 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 ff 15 90 00 } //01 00 
		$a_00_3 = {30 04 1e 46 3b f7 7c } //00 00 
	condition:
		any of ($a_*)
 
}