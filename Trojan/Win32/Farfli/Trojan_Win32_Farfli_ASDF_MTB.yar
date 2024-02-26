
rule Trojan_Win32_Farfli_ASDF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 8b 45 04 0f b6 04 10 30 04 0b 83 c1 01 39 cf 75 } //01 00 
		$a_01_1 = {83 ec 08 c7 04 24 e0 2e 00 00 ff 15 } //01 00 
		$a_01_2 = {66 75 63 6b 79 6f 75 } //00 00  fuckyou
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_ASDF_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 10 8b f1 0f be 04 07 99 f7 7d 0c 8b 45 08 80 c2 4f 30 14 01 b8 cd cc cc cc f7 e1 41 c1 ea 02 8d 04 92 8d 57 01 33 ff 3b f0 0f 45 fa 3b cb 7c } //01 00 
		$a_01_1 = {56 47 42 4c 67 74 56 52 66 77 43 74 77 64 4e } //00 00  VGBLgtVRfwCtwdN
	condition:
		any of ($a_*)
 
}