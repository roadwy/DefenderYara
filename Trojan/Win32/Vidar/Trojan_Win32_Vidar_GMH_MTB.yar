
rule Trojan_Win32_Vidar_GMH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 74 68 65 6d 69 64 61 } //01 00  .themida
		$a_01_1 = {65 6a 6b 49 69 6e 70 7a 71 76 78 } //01 00  ejkIinpzqvx
		$a_01_2 = {63 68 6d 6f 73 64 69 6b } //01 00  chmosdik
		$a_01_3 = {56 6f 75 77 68 64 68 6a } //01 00  Vouwhdhj
		$a_01_4 = {2e 62 6f 6f 74 } //00 00  .boot
	condition:
		any of ($a_*)
 
}