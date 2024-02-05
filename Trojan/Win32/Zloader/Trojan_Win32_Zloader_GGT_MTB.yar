
rule Trojan_Win32_Zloader_GGT_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b c1 8b f1 c1 f8 90 01 01 83 e6 90 01 01 8d 1c 85 90 01 04 c1 e6 90 01 01 8b 03 8a 44 30 90 01 01 a8 01 0f 84 90 01 04 33 ff 39 7d 10 89 7d f8 89 7d f0 75 07 90 00 } //01 00 
		$a_01_1 = {37 6b 77 69 66 68 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}