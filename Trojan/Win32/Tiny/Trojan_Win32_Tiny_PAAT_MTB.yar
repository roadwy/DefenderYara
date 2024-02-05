
rule Trojan_Win32_Tiny_PAAT_MTB{
	meta:
		description = "Trojan:Win32/Tiny.PAAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 45 fa 8b c8 89 1d 4c 86 40 00 c1 e8 04 83 e1 03 83 e0 01 89 0d 54 86 40 00 8a 0d 60 83 40 00 a3 50 86 40 00 b8 61 83 40 00 3a cb a3 24 83 40 00 74 0c } //01 00 
		$a_01_1 = {43 3a 5c 6b 61 73 6f 66 74 5c } //01 00 
		$a_01_2 = {6e 5c 62 6f 6f 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}