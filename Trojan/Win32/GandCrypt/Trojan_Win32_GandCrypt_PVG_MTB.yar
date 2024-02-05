
rule Trojan_Win32_GandCrypt_PVG_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 57 05 c3 9e 26 00 57 a3 90 01 04 ff 15 90 01 04 a0 90 01 04 30 04 1e 46 3b 75 08 7c 90 00 } //01 00 
		$a_02_1 = {56 8b 45 08 8d 34 07 e8 90 01 04 30 06 47 3b 7d 0c 7c 90 01 01 5e 90 00 } //01 00 
		$a_02_2 = {8b 4d fc 33 cd 25 ff 7f 00 00 e8 90 01 04 c9 c3 90 09 07 00 0f b7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}